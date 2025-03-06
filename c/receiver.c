#include "gen.h"
#include "totp.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <uwsc/uwsc.h>

#define MAX_CONNS 2
#define RECONNECT_INTERVAL_SECS 15

typedef struct ws_state ws_state;

typedef struct ws_client
{
	ws_state* state;

	int id;
	bool cleanup;

	// libuwsc frees the client on close/error
	// it's not idempotent to call free again...
	bool ws_initialised;
	struct uwsc_client ws_client;

	int paired_fd;
	struct ev_io paired_fd_watcher;
} ws_client;

struct ws_state
{
	struct ev_loop* loop;
	struct ev_idle cleanup_watcher;
	struct ev_signal signal_watcher;
	struct ev_timer init_watcher;

	const char* ws_url;
	int ping_interval;

	struct sockaddr_in server_addr;

	ws_client clients[MAX_CONNS];
};

static void schedule_cleanup(ws_client* wsc)
{
	if (wsc->cleanup)
	{
		log_debug("[con-%d] discarding redundant cleanup\n", wsc->id);
		return;
	}

	log_info("[con-%d] marked for cleanup\n", wsc->id);
	wsc->cleanup = true;

	if (!ev_is_active(&wsc->state->cleanup_watcher))
	{
		log_info("[con-%d] scheduling cleanup callback\n", wsc->id);
		ev_idle_start(wsc->state->loop, &wsc->state->cleanup_watcher);
	}
}

static void ws_onopen(struct uwsc_client* cl)
{
	ws_client* wsc = (ws_client*)cl->ext;

	log_info("[con-%d] open - login\n", wsc->id);

	char login_buf[256];
	int totp = generate_totp(SRV_SECRET, sizeof(SRV_SECRET), ev_now(wsc->state->loop));
	snprintf(login_buf, sizeof(login_buf), "{\"as_receiver\":true,\"token\":\"%06d\"}", totp);
	wsc->ws_client.send(&wsc->ws_client, login_buf, strlen(login_buf), UWSC_OP_TEXT);
}

static void srv_read(struct ev_loop* loop, struct ev_io* w, int revents)
{
	ws_client* wsc = (ws_client*)w->data;
	if (wsc->cleanup || wsc->paired_fd <= 0)
	{
		log_warn("[con-%d] discarding unpaired fd read fd=%d\n", wsc->id, wsc->paired_fd);
		schedule_cleanup(wsc);
		return;
	}

	char buf[8192];
	int nr = recv(wsc->paired_fd, buf, sizeof(buf) - 1, 0);
	log_info("[con-%d] read %d bytes\n", wsc->id, nr);

	if (nr > 0)
	{
		wsc->ws_client.send(&wsc->ws_client, buf, nr, UWSC_OP_BINARY);
	}
}

static void ws_onmessage(struct uwsc_client* cl, void* data, size_t len,
	bool binary)
{
	ws_client* wsc = (ws_client*)cl->ext;
	log_info("[con-%d] ws message %zu bytes, binary=%d\n", wsc->id, len, binary);

	if (wsc->cleanup || !binary)
	{
		log_warn("[con-%d] discarding ws message size=%zu, binary=%d, in_cleanup=%d\n",
			wsc->id, len, binary, wsc->cleanup);
		return;
	}

	if (wsc->paired_fd == -1)
	{
		wsc->paired_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (connect(wsc->paired_fd, (struct sockaddr*)&wsc->state->server_addr,
				sizeof(wsc->state->server_addr)) == -1)
		{
			log_err("[con-%d] connect failed: %s\n", wsc->id, strerror(errno));
			schedule_cleanup(wsc);
			return;
		}

		ev_io_init(&wsc->paired_fd_watcher, srv_read, wsc->paired_fd, EV_READ);
		ev_io_start(wsc->state->loop, &wsc->paired_fd_watcher);
	}

	if (send(wsc->paired_fd, data, len, 0) == -1)
	{
		log_err("[con-%d] failed to send to fd=%d: %s\n",
			wsc->id, wsc->paired_fd, strerror(errno));
		schedule_cleanup(wsc);
	}
}

static void ws_onerror(struct uwsc_client* cl, int err, const char* msg)
{
	ws_client* wsc = (ws_client*)cl->ext;

	log_info("[con-%d] error: %d %s\n", wsc->id, err, msg);
	wsc->ws_initialised = false; // libuwsc frees
	schedule_cleanup(wsc);
}

static void ws_onclose(struct uwsc_client* cl, int code, const char* reason)
{
	ws_client* wsc = (ws_client*)cl->ext;

	log_info("[con-%d] close: %d %s\n", wsc->id, code, reason);
	wsc->ws_initialised = false; // libuwsc frees
	schedule_cleanup(wsc);
}

static void init_client(ws_state* state, ws_client* wsc, int id)
{
	if (wsc->state != NULL)
	{
		log_debug("[con-%d] skipping re-initialisation\n", wsc->id);
		assert(id == wsc->id);
		return;
	}

	wsc->state = state;
	wsc->id = id;
	wsc->paired_fd = -1;
	wsc->paired_fd_watcher.data = wsc;

	if (uwsc_init(&wsc->ws_client, state->loop, state->ws_url,
			state->ping_interval, NULL) < 0)
	{
		log_err("[con-%d] failed to init ws conn\n", wsc->id);
		schedule_cleanup(wsc);
		return;
	}
	wsc->ws_client.ext = wsc;
	wsc->ws_client.onopen = ws_onopen;
	wsc->ws_client.onmessage = ws_onmessage;
	wsc->ws_client.onerror = ws_onerror;
	wsc->ws_client.onclose = ws_onclose;
	wsc->ws_initialised = true;
}

static void init_cb(struct ev_loop* loop, struct ev_timer* t, int revents)
{
	log_info("Initialising clients\n");

	ws_state* state = (ws_state*)t->data;
	assert(state->loop == loop);
	assert(&state->init_watcher == t);
	ev_timer_stop(state->loop, &state->init_watcher);

	for (int i = 0; i < MAX_CONNS; ++i)
	{
		init_client(state, &state->clients[i], i);
	}
}

static void cleanup_cb(struct ev_loop* loop, struct ev_idle* w, int revents)
{
	log_info("Cleanup running\n");

	ws_state* state = (ws_state*)w->data;
	assert(state->loop == loop);
	assert(&state->cleanup_watcher == w);
	ev_idle_stop(state->loop, &state->cleanup_watcher);

	for (int i = 0; i < MAX_CONNS; ++i)
	{
		ws_client* wsc = &state->clients[i];
		if (wsc->cleanup)
		{
			if (ev_is_active(&wsc->paired_fd_watcher))
			{
				log_info("[con-%d] closing paired fd watcher\n", wsc->id);
				ev_io_stop(state->loop, &wsc->paired_fd_watcher);
			}
			if (wsc->paired_fd > 0)
			{
				int status = close(wsc->paired_fd);
				log_info("[con-%d] closed socket fd=%d, status=%d\n",
					wsc->id, wsc->paired_fd, status);
			}
			if (wsc->ws_initialised)
			{
				log_info("[con-%d] closing websocket client\n", wsc->id);
				wsc->ws_client.free(&wsc->ws_client);
			}

			log_info("[con-%d] finished cleanup\n", wsc->id);
			memset(wsc, 0, sizeof(ws_client));
		}
	}

	if (!ev_is_active(&state->init_watcher))
	{
		log_info("Scheduling re-initialisation in %d seconds\n", RECONNECT_INTERVAL_SECS);
		ev_timer_init(&state->init_watcher, init_cb, RECONNECT_INTERVAL_SECS, 0.0);
		ev_timer_start(state->loop, &state->init_watcher);
	}
	else
	{
		log_debug("Re-init timer already scheduled");
	}
}

static void signal_cb(struct ev_loop* loop, ev_signal* w, int revents)
{
	if (w->signum == SIGINT)
	{
		ev_break(loop, EVBREAK_ALL);
		log_info("Quitting from SIGINT\n");
	}
}

int main(int argc, char* argv[])
{
	ws_state state;
	memset(&state, 0, sizeof(ws_state));

	state.loop = EV_DEFAULT;
	state.signal_watcher.data = &state;
	state.cleanup_watcher.data = &state;
	state.init_watcher.data = &state;
	state.ping_interval = 10;
	state.server_addr.sin_family = AF_INET;

	uwsc_load_ca_crt_file("DigiCertGlobalRootG2.crt");
	log_level(LOG_INFO);

	if (argc != 4)
	{
		fprintf(stderr, "Usage: %s ws://path-to/relay 127.0.0.1 1234\n", argv[0]);
		return 1;
	}

	state.ws_url = argv[1];
	state.server_addr.sin_port = atoi(argv[3]);

	if (inet_pton(AF_INET, argv[2], &state.server_addr.sin_addr) <= 0)
	{
		const char* err = strerror(errno);
		log_err("Invalid server address: %s: %s\n", argv[2], err);
		return 1;
	}

	log_info("WS relay: %s <-> %s:%d\n", state.ws_url, argv[2], state.server_addr.sin_port);

	ev_idle_init(&state.cleanup_watcher, cleanup_cb);
	ev_signal_init(&state.signal_watcher, signal_cb, SIGINT);
	ev_timer_init(&state.init_watcher, init_cb, RECONNECT_INTERVAL_SECS, 0.0);
	ev_signal_start(state.loop, &state.signal_watcher);

	init_cb(state.loop, &state.init_watcher, 0);
	ev_run(state.loop, 0);

	return 0;
}