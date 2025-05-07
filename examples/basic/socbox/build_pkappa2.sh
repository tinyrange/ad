set -e
cd pkappa2/web
npm i
npm run build
cd ..
GOOS=linux go build cmd/pkappa2/main.go

rm -rf build
mkdir build
cp -R converters build
cp -R web/dist build
cp main build
