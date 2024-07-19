# quizzy

A simple dockerized self hostable quiz app which use a `libSQL` database from [Turso](https://turso.tech/).

## Technologies

- [PicoCSS](https://picocss.com)
- [libSQl](https://github.com/tursodatabase/libsql)
- [Nix](https://nixos.org/)
- [HTMX](https://htmx.org/)

## Local Installation

### Install prebuilt binaries via shell script (MacOS and Linux)

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/frectonz/quizzy/releases/download/0.1.1/quizzy-installer.sh | sh
```

### Install prebuilt binaries via powershell script (Windows)

```sh
powershell -c "irm https://github.com/frectonz/quizzy/releases/download/0.1.1/quizzy-installer.ps1 | iex"
```

### Updating

```bash
quizzy-update
```

## Nix

```bash
nix shell github:frectonz/quizzy
```

## Using the docker image

The docker image is available on the [Docker Hub](https://hub.docker.com/r/frectonz/quizzy). You can use this docker image to deploy `quizzy` on any platform you want.

```
docker pull frectonz/quizzy
docker run -p 1414:1414 \
      -e ADDRESS="0.0.0.0:1414" \
      -e URL="libsql://<name>.turso.io" \
      -e AUTH_TOKEN="<token>" \
      frectonz/quizzy
```

### Environment variables

- `ADDRESS` - the address to bind to, example `0.0.0.0:1414`
- `URL` - libSQL server address from Turso, example `libsql://my-quiz.turso.io`
- `AUTH_TOKEN` - libSQL authentication token from Turso, must support read and write actions.
