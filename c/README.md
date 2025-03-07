# wsrelay

## Build

```
git submodule update --init --recursive

pushd thirdparty/libuwsc
mkdir build
cd build
cmake -GNinja .. -DUSE_MBEDTLS=1
ninja
DESTDIR=../a ninja install
popd

mkdir build
cd build
export WSRELAY_SRV_SECRET=...
cmake .. -GNinja -DCMAKE_PREFIX_PATH=$(realpath ../thirdparty/libuwsc/a/usr/local/)
ninja
```
