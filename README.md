# quizzy

A simple dockerized self hostable quiz app which use a `libSQL` database from [Turso](https://turso.tech/).

One thing that makes `quizzy` special is quizzes are imported not through inputs and forms but from one JSON file that has all the questions. Here's an example of a quiz with 3 questions from the book 1984.

```json
[
  {
    "question": "What is the uniform of the party?",
    "options": [
      { "text": "Green Overalls", "isAnswer": false },
      { "text": "Blue Overall", "isAnswer": true },
      { "text": "Yellow Overalls", "isAnswer": false }
    ]
  },
  {
    "question": "What is the language of Oceania?",
    "options": [
      { "text": "Newspeak", "isAnswer": true },
      { "text": "Oldspeak", "isAnswer": false },
      { "text": "OceaniaSpeak", "isAnswer": false }
    ]
  },
  {
    "question": "What happens to people accused of Thoughtcrime?",
    "options": [
      { "text": "KILLED", "isAnswer": false },
      { "text": "BOILED", "isAnswer": false },
      { "text": "VAPORIZED", "isAnswer": true }
    ]
  }
]
```

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
