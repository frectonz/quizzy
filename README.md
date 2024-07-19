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
