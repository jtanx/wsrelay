#include "gen.h"
#include "totp.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <uwsc/uwsc.h>

#define MAX_CONNS 2

typedef struct ws_state ws_state;

typedef struct ws_client
{
	ws_state* state;

	struct uwsc_client ws_client;

	int paired_fd;
	struct ev_io paired_fd_watcher;
} ws_client;

struct ws_state
{
	struct ev_loop* loop;
	struct ev_signal signal_watcher;

	const char* ws_url;
	int ping_interval;

	struct sockaddr_in server_addr;

	ws_client clients[MAX_CONNS];
};

static void ws_onopen(struct uwsc_client* cl)
{
	printf("OPEN\n");
	// log(WS open)
}

static void srv_read(struct ev_loop* loop, struct ev_io* w, int revents)
{
	ws_client* wsc = (ws_client*)w->data;

	printf("SRV READ\n");
	char buf[8192];
	int nr = recv(wsc->paired_fd, buf, sizeof(buf) - 1, 0);
	if (nr > 0)
	{
		wsc->ws_client.send(&wsc->ws_client, buf, nr, UWSC_OP_BINARY);
	}
}

static void ws_onmessage(struct uwsc_client* cl, void* data, size_t len,
	bool binary)
{
	printf("WS MESSAGE\n");
	if (!binary)
	{
		// log(unexpected binary)
		return;
	}

	ws_client* wsc = (ws_client*)cl->ext;
	if (wsc->paired_fd == -1)
	{
		wsc->paired_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (connect(wsc->paired_fd, (struct sockaddr*)&wsc->state->server_addr,
				sizeof(wsc->state->server_addr)) == -1)
		{
			// log(ERROR)
			return;
		}

		ev_io_init(&wsc->paired_fd_watcher, srv_read, wsc->paired_fd, EV_READ);
		ev_io_start(wsc->state->loop, &wsc->paired_fd_watcher);
	}

	send(wsc->paired_fd, data, len, 0);
}

static void ws_onerror(struct uwsc_client* cl, int err, const char* msg)
{
	printf("WS ERROR: %d %s\n", err, msg);
}

static void ws_onclose(struct uwsc_client* cl, int code, const char* reason)
{
	printf("WS CLOSE: %d %s\n", code, reason);
}

static int init_client(ws_state* state, ws_client* wsc)
{
	wsc->state = state;
	wsc->paired_fd = -1;
	wsc->paired_fd_watcher.data = wsc;

	if (uwsc_init(&wsc->ws_client, state->loop, state->ws_url,
			state->ping_interval, NULL) < 0)
	{
		return 0;
	}
	wsc->ws_client.ext = wsc;
	wsc->ws_client.onopen = ws_onopen;
	wsc->ws_client.onmessage = ws_onmessage;
	wsc->ws_client.onerror = ws_onerror;
	wsc->ws_client.onclose = ws_onclose;

	char login_buf[256];
	int totp = generate_totp(SRV_SECRET, sizeof(SRV_SECRET), ev_now(wsc->state->loop));
	snprintf(login_buf, sizeof(login_buf), "{\"as_receiver\":true,\"token\":\"%06d\"}", totp);
	wsc->ws_client.send(&wsc->ws_client, login_buf, strlen(login_buf), UWSC_OP_TEXT);

	return 1;
}

static void signal_cb(struct ev_loop* loop, ev_signal* w, int revents)
{
	if (w->signum == SIGINT)
	{
		ev_break(loop, EVBREAK_ALL);
		// log_info("Normal quit\n");
	}
}

int main(int argc, char* argv[])
{
	ws_state state;
	state.loop = EV_DEFAULT;
	state.signal_watcher.data = &state;
	state.ping_interval = 10;
	state.server_addr.sin_family = AF_INET;

	if (argc != 4)
	{
		fprintf(stderr, "Usage: %s ws://path-to/relay 127.0.0.1 1234\n", argv[0]);
		return 1;
	}

	state.ws_url = argv[1];
	state.server_addr.sin_port = atoi(argv[3]);

	printf("%s\n", state.ws_url);

	if (inet_pton(AF_INET, argv[2], &state.server_addr.sin_addr) <= 0)
	{
		perror("Invalid server address");
		return 1;
	}

	for (int i = 0; i < MAX_CONNS; ++i)
	{
		init_client(&state, &state.clients[i]);
	}

	ev_signal_init(&state.signal_watcher, signal_cb, SIGINT);
	ev_signal_start(state.loop, &state.signal_watcher);

	ev_run(state.loop, 0);

	return 0;
}