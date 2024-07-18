use clap::Parser;
use db::Db;
use futures::{future::OptionFuture, FutureExt};
use warp::Filter;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// libSQL server address
    url: String,

    /// libSQL authentication token.
    auth_token: String,

    /// The address to bind to.
    #[arg(short, long, default_value = "127.0.0.1:1414")]
    address: String,
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| "tracing=info,warp=debug,quizzy=debug".to_owned());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    let args = Args::parse();

    let db = Db::new(args.url, args.auth_token).await?;
    let routes = routes(db);
    let static_files = warp::path("static").and(statics::routes());
    let routes = static_files
        .or(routes)
        .recover(rejections::handle_rejection);

    let address = args.address.parse::<std::net::SocketAddr>()?;
    warp::serve(routes).run(address).await;

    Ok(())
}

pub fn routes(
    conn: db::Db,
) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    homepage::route(conn.clone()).or(quiz::route(conn.clone()))
}

fn with_state<T: Clone + Send>(
    db: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}

mod statics {
    use std::path::Path;

    use include_dir::{include_dir, Dir};
    use warp::{
        http::{
            header::{CACHE_CONTROL, CONTENT_TYPE},
            Response,
        },
        Filter,
    };

    static STATIC_DIR: Dir = include_dir!("static");

    async fn send_file(path: warp::path::Tail) -> Result<impl warp::Reply, warp::Rejection> {
        let path = Path::new(path.as_str());
        let file = STATIC_DIR
            .get_file(path)
            .ok_or_else(warp::reject::not_found)?;

        let content_type = match file.path().extension() {
            Some(ext) if ext == "css" => "text/css",
            Some(ext) if ext == "svg" => "image/svg+xml",
            Some(ext) if ext == "js" => "text/javascript",
            _ => "application/octet-stream",
        };

        let resp = Response::builder()
            .header(CONTENT_TYPE, content_type)
            .header(CACHE_CONTROL, "max-age=3600, must-revalidate")
            .body(file.contents())
            .unwrap();

        Ok(resp)
    }

    pub fn routes() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path::tail().and_then(send_file)
    }
}

trait FutureOptionExt<T> {
    fn to_future(self) -> OptionFuture<T>;
}

impl<T> FutureOptionExt<T> for Option<T> {
    fn to_future(self) -> OptionFuture<T> {
        OptionFuture::from(self)
    }
}

mod db {
    use std::sync::Arc;

    use color_eyre::{eyre::OptionExt, Result};
    use futures::{future, StreamExt, TryStreamExt};
    use libsql::params;
    use ulid::Ulid;

    use crate::model::{Question, Questions};

    pub struct Quiz {
        pub id: i32,
        pub name: String,
        pub count: i32,
    }

    pub struct QuestionModel {
        pub question: String,
        pub options: Vec<QuestionOptionModel>,
    }

    pub struct QuestionOptionModel {
        pub id: i32,
        pub is_answer: bool,
        pub option: String,
    }

    pub struct SubmissionModel {
        pub id: i32,
        pub quiz_id: i32,
        pub question_idx: i32,
    }

    #[derive(Clone)]
    pub struct Db {
        db: Arc<libsql::Database>,
    }

    impl Db {
        pub async fn new(url: String, auth_token: String) -> Result<Self> {
            let db = libsql::Builder::new_remote(url.to_owned(), auth_token)
                .build()
                .await?;

            let conn = db.connect()?;
            let one = conn
                .query("SELECT 1", ())
                .await?
                .next()
                .await?
                .ok_or_eyre("connection check failed")?
                .get::<i32>(0)?;
            assert_eq!(one, 1);

            conn.execute(
                r#"
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY,
                password TEXT NOT NULL
            )
                "#,
                (),
            )
            .await?;

            conn.execute(
                r#"
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY
            )
                "#,
                (),
            )
            .await?;

            conn.execute(
                r#"
            CREATE TABLE IF NOT EXISTS quizzes (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            )
                "#,
                (),
            )
            .await?;

            conn.execute(
                r#"
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY,
                question TEXT NOT NULL,
                quiz_id INTEGER NOT NULL,
                FOREIGN KEY(quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE
            )
                "#,
                (),
            )
            .await?;

            conn.execute(
                r#"
            CREATE TABLE IF NOT EXISTS options (
                id INTEGER PRIMARY KEY,
                option TEXT NOT NULL,
                is_answer BOOLEAN NOT NULL,
                question_id INTEGER NOT NULL,
                FOREIGN KEY(question_id) REFERENCES questions(id) ON DELETE CASCADE
            )
                "#,
                (),
            )
            .await?;

            conn.execute(
                r#"
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                cookie TEXT NOT NULL,
                question_idx INTEGER,
                quiz_id INTEGER NOT NULL,
                FOREIGN KEY(quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE
            )
                "#,
                (),
            )
            .await?;

            conn.execute(
                r#"
            CREATE TABLE IF NOT EXISTS answers (
                id INTEGER PRIMARY KEY,
                is_correct BOOLEAN NOT NULL,
                answer_id INTEGER NOT NULL,
                question_id INTEGER NOT NULL,
                submission_id INTEGER NOT NULL,
                FOREIGN KEY(answer_id) REFERENCES options(id) ON DELETE CASCADE,
                FOREIGN KEY(question_id) REFERENCES questions(id) ON DELETE CASCADE,
                FOREIGN KEY(submission_id) REFERENCES submissions(id) ON DELETE CASCADE
            )
                "#,
                (),
            )
            .await?;

            tracing::info!("database connection has been verified");

            Ok(Self { db: Arc::new(db) })
        }

        pub async fn admin_password(&self) -> Result<Option<String>> {
            let conn = self.db.connect()?;
            let query = conn
                .query("SELECT password FROM admin WHERE id = 1", ())
                .await?
                .next()
                .await?;

            Ok(match query {
                Some(row) => Some(row.get::<String>(0)?),
                None => None,
            })
        }

        pub async fn set_admin_password(&self, password: String) -> Result<()> {
            let conn = self.db.connect()?;

            let rows = conn
                .execute("INSERT INTO admin (password) VALUES (?)", params![password])
                .await?;

            tracing::info!("new admin password set: {rows:?}");
            Ok(())
        }

        pub async fn create_session(&self) -> Result<String> {
            let session = Ulid::new().to_string();
            let conn = self.db.connect()?;

            let rows = conn
                .execute(
                    "INSERT INTO sessions (id) VALUES (?)",
                    params![session.clone()],
                )
                .await?;

            tracing::info!("new session {session:?} created : {rows:?}");
            Ok(session)
        }

        pub async fn session_exists(&self, session: String) -> Result<bool> {
            let conn = self.db.connect()?;
            let exists = conn
                .query(
                    "SELECT id FROM sessions WHERE id = ?",
                    params![session.clone()],
                )
                .await?
                .next()
                .await?
                .is_some();

            tracing::info!("session {session:?} exists: {exists}");
            Ok(exists)
        }

        pub async fn load_quiz(&self, quiz_name: String, questions: Questions) -> Result<i32> {
            let conn = self.db.connect()?;
            let quiz_id = conn
                .query(
                    "INSERT INTO quizzes (name) VALUES (?) RETURNING id",
                    params![quiz_name],
                )
                .await?
                .next()
                .await?
                .ok_or_eyre("could not get quiz id")?
                .get::<i32>(0)?;

            for Question { question, options } in questions {
                let question_id = conn
                    .query(
                        "INSERT INTO questions (question, quiz_id) VALUES (?, ?) RETURNING id",
                        params![question, quiz_id],
                    )
                    .await?
                    .next()
                    .await?
                    .ok_or_eyre("could not get question id")?
                    .get::<i32>(0)?;

                for option in options {
                    conn.execute(
                        "INSERT INTO options (option, is_answer, question_id) VALUES (?, ?, ?)",
                        params![option.text, option.is_answer, question_id],
                    )
                    .await?;
                }
            }

            tracing::info!("new quiz created with id: {quiz_id}");
            Ok(quiz_id)
        }

        pub async fn quizzes(&self) -> Result<Vec<Quiz>> {
            let conn = self.db.connect()?;

            let quizzes = conn
                .query(
                    r#"
            SELECT
              quizzes.id,
              quizzes.name,
              COUNT(questions.id) AS question_count
            FROM
              quizzes
              JOIN questions ON questions.quiz_id = quizzes.id
            GROUP BY
              quizzes.name
                    "#,
                    (),
                )
                .await?
                .into_stream()
                .map_ok(|r| Quiz {
                    id: r.get::<i32>(0).expect("could not get quiz id"),
                    name: r.get::<String>(1).expect("could not get quiz name"),
                    count: r.get::<i32>(2).expect("could not get questions count"),
                })
                .filter_map(|r| future::ready(r.ok()))
                .collect::<Vec<_>>()
                .await;

            Ok(quizzes)
        }

        pub async fn delete_quiz(&self, quiz_id: i32) -> Result<()> {
            let conn = self.db.connect()?;

            conn.execute("DELETE FROM quizzes WHERE id = ?", params![quiz_id])
                .await?;

            tracing::info!("quiz deleted with id: {quiz_id}");
            Ok(())
        }

        pub async fn quiz_name(&self, quiz_id: i32) -> Result<String> {
            let conn = self.db.connect()?;

            let quiz_name = conn
                .query("SELECT name FROM quizzes WHERE id = ?", params![quiz_id])
                .await?
                .next()
                .await?
                .ok_or_eyre("could not get quiz name")?
                .get::<String>(0)?;

            Ok(quiz_name)
        }

        pub async fn create_submission(&self, name: &str, quiz_id: i32) -> Result<String> {
            let cookie = Ulid::new().to_string();
            let cookie_str = cookie.as_str();
            let conn = self.db.connect()?;

            let rows = conn
                .execute(
                    "INSERT INTO submissions (name, cookie, quiz_id, question_idx) VALUES (?, ?, ?, 0)",
                    params![name, cookie_str, quiz_id],
                )
                .await?;

            tracing::info!("submission created for quiz={quiz_id}: {rows:?}");
            Ok(cookie)
        }

        pub async fn get_question(&self, question_id: i32) -> Result<QuestionModel> {
            let conn = self.db.connect()?;

            let question = conn
                .query(
                    "SELECT question FROM questions WHERE id = ?",
                    params![question_id],
                )
                .await?
                .next()
                .await?
                .ok_or_eyre("could not get quiz name")?
                .get::<String>(0)?;

            let options = conn
                .query(
                    "SELECT id, option, is_answer FROM options WHERE question_id = ?",
                    params![question_id],
                )
                .await?
                .into_stream()
                .map_ok(|r| QuestionOptionModel {
                    id: r.get::<i32>(0).expect("could not get option id"),
                    option: r.get::<String>(1).expect("could not get option"),
                    is_answer: r.get::<bool>(2).expect("could not get option is_answer"),
                })
                .filter_map(|r| future::ready(r.ok()))
                .collect::<Vec<_>>()
                .await;

            Ok(QuestionModel { question, options })
        }

        pub async fn question_id_from_idx(&self, quiz_id: i32, question_idx: i32) -> Result<i32> {
            let conn = self.db.connect()?;
            let question_id = conn
                .query(
                    "SELECT id FROM questions WHERE quiz_id = ? LIMIT 1 OFFSET ?",
                    params![quiz_id, question_idx],
                )
                .await?
                .next()
                .await?
                .ok_or_eyre("no question id found")?
                .get::<i32>(0)?;

            Ok(question_id)
        }

        pub async fn questions_count(&self, quiz_id: i32) -> Result<i32> {
            let conn = self.db.connect()?;
            Ok(conn
                .query(
                    "SELECT count(*) FROM questions WHERE quiz_id = ?",
                    params![quiz_id],
                )
                .await?
                .next()
                .await?
                .ok_or_eyre("could not get questions count")?
                .get::<i32>(0)?)
        }

        pub async fn get_submission(&self, cookie: &str) -> Result<SubmissionModel> {
            let conn = self.db.connect()?;
            conn.query(
                "SELECT id, quiz_id, question_idx FROM submissions WHERE cookie = ?",
                params![cookie],
            )
            .await?
            .next()
            .await?
            .map(|r| SubmissionModel {
                id: r.get::<i32>(0).expect("failed to get submission id"),
                quiz_id: r.get::<i32>(1).expect("failed to get quiz id"),
                question_idx: r.get::<i32>(2).expect("failed to get question index"),
            })
            .ok_or_eyre("could not get submission")
        }

        pub async fn create_answer(
            &self,
            quiz_id: i32,
            submission_id: i32,
            question_idx: i32,
            answer_id: i32,
        ) -> Result<()> {
            let conn = self.db.connect()?;

            let is_correct = conn
                .query(
                    "SELECT is_answer FROM options WHERE id = ?",
                    params![answer_id],
                )
                .await?
                .next()
                .await?
                .ok_or_eyre("no option found")?
                .get::<bool>(0)?;

            let question_id = self.question_id_from_idx(quiz_id, question_idx).await?;
            let rows = conn
                .execute(
                    "INSERT INTO answers (is_correct, answer_id, question_id, submission_id) VALUES (?, ?, ?, ?)",
                    params![is_correct, answer_id, question_id, submission_id],
                )
                .await?;

            tracing::info!(
                "answer created for in submission={submission_id} quiz={quiz_id}: {rows:?}"
            );

            Ok(())
        }

        pub async fn increase_question_index(&self, submission_id: i32) -> Result<()> {
            let conn = self.db.connect()?;

            let rows = conn
                .execute(
                    "UPDATE submissions SET question_idx = question_idx + 1 WHERE id = ?",
                    params![submission_id],
                )
                .await?;

            tracing::info!("question index increased for submission={submission_id}: {rows:?}");
            Ok(())
        }
    }
}

mod views {
    use maud::{html, Markup, DOCTYPE};

    use crate::utils;

    fn css() -> Markup {
        html! {
            link rel="stylesheet" href="/static/pico.min.css";
            link rel="stylesheet" href="/static/index.css";
        }
    }

    fn js() -> Markup {
        html! {
            script src="/static/htmx/htmx.min.js" {}
            script src="/static/htmx/ext/json-enc.js" {}
        }
    }

    fn icon() -> Markup {
        html! {
            link rel="icon" href="/static/img/icon.svg" type="image/svg+xml" {}
        }
    }

    fn header() -> Markup {
        html! {
            header {
                nav {
                    ul {
                        li."secondary" {
                            a href="/" {
                                strong { "Quizzy" }
                            }
                        }
                    }
                    ul {
                        li."secondary" { (utils::VERSION) }
                        li { a href="https://github.com/frectonz/quizzy" { "GitHub" } }
                    }
                }
            }
        }
    }

    fn main(body: Markup) -> Markup {
        html! {
            main { (body) }
        }
    }

    pub fn page(title: &str, body: Markup) -> Markup {
        html! {
            (DOCTYPE)
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="color-scheme" content="light dark";

                (css())
                (js())
                (icon())

                title { (format!("{title} - Quizzy")) }
            }

            body."container" {
                (header())
                (main(body))
            }
        }
    }

    pub fn titled(title: &str, body: Markup) -> Markup {
        html! {
            title { (title) " - Quizzy" }
            (body)
        }
    }
}

pub fn is_authorized(
    db: Db,
) -> impl Filter<Extract = ((),), Error = warp::reject::Rejection> + Clone {
    warp::any()
        .and(with_state(db.clone()))
        .and(warp::cookie::optional::<String>(names::SESSION_COOKIE_NAME))
        .and_then(authorized)
}

async fn authorized(db: Db, session: Option<String>) -> Result<(), warp::Rejection> {
    let session_exists = session
        .map(|s| db.session_exists(s).map(|res| res.ok()))
        .to_future()
        .await
        .flatten()
        .unwrap_or_default();

    if session_exists {
        Ok(())
    } else {
        Err(warp::reject::custom(rejections::Unauthorized))
    }
}

pub fn is_htmx() -> impl Filter<Extract = (bool,), Error = warp::reject::Rejection> + Clone {
    warp::any()
        .and(warp::header::optional::<String>("HX-Request"))
        .map(|hx_req: Option<String>| hx_req.is_some_and(|x| x == "true"))
}

mod homepage {
    use std::collections::HashMap;

    use crate::{
        db::Db,
        is_authorized, model, names, quiz,
        rejections::{InputError, InternalServerError},
        utils, views, with_state, FutureOptionExt,
    };

    use futures::FutureExt;
    use maud::{html, Markup};
    use serde::Deserialize;
    use warp::{
        filters::multipart::FormData,
        http::{header::SET_COOKIE, Response},
        reject::Rejection,
        reply::Reply,
        Filter,
    };

    pub fn route(
        conn: Db,
    ) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        let homepage = warp::path::end()
            .and(warp::get())
            .and(with_state(conn.clone()))
            .and(warp::cookie::optional::<String>(names::SESSION_COOKIE_NAME))
            .and_then(homepage);

        let get_started_post = warp::path("start")
            .and(warp::post())
            .and(with_state(conn.clone()))
            .and(warp::body::json::<GetStartedPost>())
            .and_then(get_started_post);

        let login_post = warp::path("login")
            .and(warp::post())
            .and(with_state(conn.clone()))
            .and(warp::body::json::<LoginPost>())
            .and_then(login_post);

        let create_quiz = warp::path("create-quiz")
            .and(warp::post())
            .and(is_authorized(conn.clone()))
            .and(with_state(conn.clone()))
            .and(warp::multipart::form())
            .and_then(create_quiz);

        let delete_quiz = is_authorized(conn.clone())
            .and(with_state(conn.clone()))
            .and(warp::delete())
            .and(warp::path!("delete-quiz" / i32))
            .and_then(delete_quiz);

        homepage
            .or(get_started_post)
            .or(login_post)
            .or(create_quiz)
            .or(delete_quiz)
    }

    async fn homepage(
        db: Db,
        session: Option<String>,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let session_exists = session
            .map(|s| db.session_exists(s).map(|res| res.ok()))
            .to_future()
            .await
            .flatten()
            .unwrap_or_default();

        if session_exists {
            Ok(views::page("Dashboard", dashboard(&db).await?))
        } else {
            let admin_password = db.admin_password().await.map_err(|e| {
                tracing::error!("could not get admin password: {e}");
                warp::reject::custom(InternalServerError)
            })?;

            match admin_password {
                Some(_) => Ok(views::page("Welcome Back", login(LoginState::NoError))),
                None => Ok(views::page("Get Started", get_started())),
            }
        }
    }

    #[derive(Deserialize)]
    struct GetStartedPost {
        admin_password: String,
    }

    async fn get_started_post(
        db: Db,
        body: GetStartedPost,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        db.set_admin_password(body.admin_password)
            .await
            .map_err(|e| {
                tracing::error!("could not set admin password: {e}");
                warp::reject::custom(InternalServerError)
            })?;

        let session = db.create_session().await.map_err(|e| {
            tracing::error!("could not create a new session: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        let cookie = utils::cookie(names::SESSION_COOKIE_NAME, &session);
        let resp = Response::builder()
            .header(SET_COOKIE, cookie)
            .body(views::titled("Dashboard", dashboard(&db).await?).into_string())
            .unwrap();

        Ok(resp)
    }

    #[derive(Deserialize)]
    struct LoginPost {
        admin_password: String,
    }

    async fn login_post(db: Db, body: LoginPost) -> Result<impl warp::Reply, warp::Rejection> {
        let admin_password = db.admin_password().await.map_err(|e| {
            tracing::error!("could not get admin password: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        if admin_password == Some(body.admin_password) {
            let session = db.create_session().await.map_err(|e| {
                tracing::error!("could not create a new session: {e}");
                warp::reject::custom(InternalServerError)
            })?;

            let cookie = utils::cookie(names::SESSION_COOKIE_NAME, &session);
            let resp = Response::builder()
                .header(SET_COOKIE, cookie)
                .body(views::titled("Dashboard", dashboard(&db).await?).into_string())
                .unwrap();

            Ok(resp.into_response())
        } else {
            Ok(views::titled("Welcome Back", login(LoginState::IncorrectPassword)).into_response())
        }
    }

    async fn create_quiz(
        _: (),
        db: Db,
        form: FormData,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        use bytes::BufMut;
        use futures::TryStreamExt;

        let mut field_names: HashMap<_, _> = form
            .and_then(|mut field| async move {
                let mut bytes: Vec<u8> = Vec::new();

                while let Some(content) = field.data().await {
                    let content = content.unwrap();
                    bytes.put(content);
                }
                Ok((
                    field.name().to_string(),
                    String::from_utf8_lossy(&bytes).to_string(),
                ))
            })
            .try_collect()
            .await
            .map_err(|e| {
                tracing::error!("failed to decode form data: {e}");
                warp::reject::custom(InputError)
            })?;

        let quiz_name = field_names
            .remove("quiz_name")
            .ok_or_else(|| warp::reject::custom(InputError))?;

        let quiz_file = field_names
            .remove("quiz_file")
            .ok_or_else(|| warp::reject::custom(InputError))?;

        let questions = serde_json::from_str::<model::Questions>(&quiz_file).map_err(|e| {
            tracing::error!("failed to decode quiz file: {e}");
            warp::reject::custom(InputError)
        })?;

        let quiz_id = db.load_quiz(quiz_name, questions).await.map_err(|e| {
            tracing::error!("failed to decode quiz file: {e}");
            warp::reject::custom(InputError)
        })?;

        let resp = Response::builder()
            .header("HX-Replace-Url", names::quiz_dashboard_url(quiz_id))
            .body(
                views::titled("Quiz Dashboard", quiz::dashboard(&db, quiz_id).await?).into_string(),
            )
            .unwrap();

        Ok(resp)
    }

    async fn delete_quiz(_: (), db: Db, quiz_id: i32) -> Result<impl warp::Reply, warp::Rejection> {
        db.delete_quiz(quiz_id).await.map_err(|e| {
            tracing::error!("failed to delete a quiz: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        Ok(html!())
    }

    fn get_started() -> Markup {
        html! {
            h1 { "Welcome to Quizzy!" }
            p {
                "Seems like this is the first time you are using "
                mark { "Quizzy" }
                " for the first time. You will need to set an "
                strong { "admin password" }
                " to get started."
            }
            article style="width: fit-content;" {
                form hx-post=(names::GET_STARTED_URL)
                     hx-ext="json-enc"
                     hx-target="main"
                     hx-disabled-elt="find input[type='password'], find input[type='submit']"
                     hx-swap="innerHTML" {
                    label {
                        "Admin Password"
                        input name="admin_password"
                              type="password"
                              autocomplete="off"
                              placeholder="Admin Password"
                              aria-describedby="password-helper"
                              aria-label="Your Password";
                        small id="password-helper" { "Be sure not to forget the password." }
                    }
                    input type="submit" value="Get Started";
                }
            }
        }
    }

    enum LoginState {
        NoError,
        IncorrectPassword,
    }

    fn login(state: LoginState) -> Markup {
        html! {
            h1 { "Welcome back to Quizzy!" }
            p {
                "Use the admin password you previously set to log back in to your dashboard."
            }
            article style="width: fit-content;" {
                form hx-post=(names::LOGIN_URL)
                     hx-ext="json-enc"
                     hx-target="main"
                     hx-disabled-elt="find input[type='password'], find input[type='submit']"
                     hx-swap="innerHTML" {
                    @match state {
                        LoginState::NoError => {
                            label {
                                "Admin Password"
                                input name="admin_password"
                                      type="password"
                                      autocomplete="off"
                                      placeholder="Admin Password"
                                      aria-describedby="password-helper"
                                      aria-label="Your Password";
                                small id="password-helper" {
                                    "Use the admin password you set when you first used Quizzy."
                                }
                            }
                        },
                        LoginState::IncorrectPassword => {
                            label {
                                "Admin Password"
                                input name="admin_password"
                                      type="password"
                                      autocomplete="off"
                                      placeholder="Admin Password"
                                      aria-describedby="password-helper"
                                      aria-invalid="true"
                                      aria-label="Your Password";
                                small id="password-helper" { "Incorrect password" }
                            }
                        }
                    }
                    input type="submit" value="Log In";
                }
            }
        }
    }

    async fn dashboard(db: &Db) -> Result<Markup, Rejection> {
        let quizzes = db.quizzes().await.map_err(|e| {
            tracing::error!("could not get quizzes from database: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        let page = html! {
            h1 { "Dashboard" }

            article style="width: fit-content;" {
                form hx-post=(names::CREATE_QUIZ_URL)
                     hx-target="main"
                     enctype="multipart/form-data"
                     hx-disabled-elt="find input[type='text'], find input[type='file'], find input[type='submit']"
                     hx-swap="innerHTML" {
                        label {
                            "Quiz Name"
                            input name="quiz_name"
                                  type="text"
                                  required="true"
                                  autocomplete="off"
                                  placeholder="Quiz Name"
                                  aria-describedby="quiz-name-helper"
                                  aria-label="Your Quiz Name";
                            small id="quiz-name-helper" { "What do you want to call this quiz?" }
                        }

                        label {
                            "Quiz File"
                            input name="quiz_file"
                                  type="file"
                                  required="true"
                                  aria-describedby="quiz-file-helper"
                                  accept="application/json"
                                  aria-label="Your Quiz File";
                            small id="quiz-file-helper" { "The JSON file that includes the questions in this quiz." }
                        }

                        input type="submit" value="Create";
                }
            }

            div."quiz-grid" {
                @for quiz in quizzes {
                    article {
                        h3 { (quiz.name) }
                        p { (quiz.count) " questions." }
                        div role="group" {
                            button
                                hx-trigger="click"
                                hx-target="main"
                                hx-swap="innerHTML"
                                hx-push-url="true"
                                hx-get=(names::quiz_dashboard_url(quiz.id)) { "View" }
                            button."contrast"
                                hx-disabled-elt="this"
                                hx-trigger="click"
                                hx-target="closest article"
                                hx-swap="outerHTML"
                                hx-confirm="Are you sure you want to delete this Quiz?"
                                hx-delete=(names::delete_quiz_url(quiz.id)) { "Delete" }
                        }
                    }
                }
            }
        };

        Ok(page)
    }
}

mod quiz {
    use maud::{html, Markup};
    use serde::Deserialize;
    use warp::{
        http::{header::SET_COOKIE, Response},
        reject::Rejection,
        Filter,
    };

    use crate::{
        db::Db,
        is_authorized, is_htmx, names,
        rejections::{InputError, InternalServerError},
        utils, views, with_state,
    };

    #[derive(Deserialize)]
    struct StartSubmissionBody {
        name: String,
    }

    #[derive(Deserialize)]
    struct SubmitAnswerBody {
        option: String,
    }

    pub fn route(
        conn: Db,
    ) -> impl warp::Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        let quiz_dashboard = is_authorized(conn.clone())
            .and(is_htmx())
            .and(with_state(conn.clone()))
            .and(warp::get())
            .and(warp::path!("quiz" / i32 / "dashboard"))
            .and_then(quiz_dashboard);

        let quiz_page = warp::get()
            .and(is_htmx())
            .and(with_state(conn.clone()))
            .and(warp::path!("quiz" / i32))
            .and(warp::cookie::optional(names::SUBMISSION_COOKIE_NAME))
            .and_then(quiz_page);

        let start_submission = warp::post()
            .and(with_state(conn.clone()))
            .and(warp::path!("start-submission" / i32))
            .and(warp::body::json::<StartSubmissionBody>())
            .and_then(start_submission);

        let submit_answer = warp::post()
            .and(with_state(conn.clone()))
            .and(warp::path!("submit-answer"))
            .and(warp::cookie(names::SUBMISSION_COOKIE_NAME))
            .and(warp::body::json::<SubmitAnswerBody>())
            .and_then(submit_answer);

        quiz_dashboard
            .or(quiz_page)
            .or(start_submission)
            .or(submit_answer)
    }

    async fn quiz_dashboard(
        _: (),
        is_htmx: bool,
        db: Db,
        quiz_id: i32,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        Ok(if is_htmx {
            views::titled("Quiz Dashboard", dashboard(&db, quiz_id).await?)
        } else {
            views::page("Quiz Dashboard", dashboard(&db, quiz_id).await?)
        })
    }

    async fn start_submission(
        db: Db,
        quiz_id: i32,
        body: StartSubmissionBody,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let sumission_cookie = db
            .create_submission(&body.name, quiz_id)
            .await
            .map_err(|e| {
                tracing::error!("could not get quiz name for quiz={quiz_id}: {e}");
                warp::reject::custom(InternalServerError)
            })?;

        let quiz_name = db.quiz_name(quiz_id).await.map_err(|e| {
            tracing::error!("could not get quiz name for quiz={quiz_id}: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        let page = views::titled(&quiz_name, question(&db, quiz_id, 0).await?);
        let cookie = utils::cookie(names::SUBMISSION_COOKIE_NAME, &sumission_cookie);
        let resp = Response::builder()
            .header(SET_COOKIE, cookie)
            .body(page.into_string())
            .unwrap();

        Ok(resp)
    }

    async fn quiz_page(
        is_htmx: bool,
        db: Db,
        quiz_id: i32,
        submission: Option<String>,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let page = match submission {
            Some(submission) => {
                let res = db.get_submission(&submission).await;

                match res {
                    Ok(submission) => {
                        question(&db, submission.quiz_id, submission.question_idx).await?
                    }
                    Err(e) => {
                        tracing::error!("could not get submission for {submission}: {e}");
                        page(&db, quiz_id).await?
                    }
                }
            }
            None => page(&db, quiz_id).await?,
        };

        if is_htmx {
            Ok(views::titled("Quiz", page))
        } else {
            Ok(views::page("Quiz", page))
        }
    }

    async fn submit_answer(
        db: Db,
        cookie: String,
        body: SubmitAnswerBody,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let submission = db.get_submission(&cookie).await.map_err(|e| {
            tracing::error!("could not get submission for {cookie}: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        let answer_id = body.option.parse::<i32>().map_err(|e| {
            tracing::error!("failed to parse answer id: {e}");
            warp::reject::custom(InputError)
        })?;

        db.create_answer(
            submission.quiz_id,
            submission.id,
            submission.question_idx,
            answer_id,
        )
        .await
        .map_err(|e| {
            tracing::error!("could not create answer for {cookie}: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        let questions_count = db.questions_count(submission.quiz_id).await.map_err(|e| {
            tracing::error!(
                "could not get question cout for quiz_id={}: {e}",
                submission.quiz_id
            );
            warp::reject::custom(InternalServerError)
        })?;

        let is_final = submission.question_idx + 1 == questions_count;

        if !is_final {
            db.increase_question_index(submission.id)
                .await
                .map_err(|e| {
                    tracing::error!("could not increase question index for {cookie}: {e}");
                    warp::reject::custom(InternalServerError)
                })?;
        }

        let page = answer(&db, submission.quiz_id, submission.question_idx, answer_id).await?;

        let resp = if is_final {
            let cookie = utils::cookie(names::SUBMISSION_COOKIE_NAME, "");
            Response::builder()
                .header(SET_COOKIE, cookie)
                .body(page.into_string())
                .unwrap()
        } else {
            Response::builder().body(page.into_string()).unwrap()
        };

        Ok(resp)
    }

    pub async fn question(db: &Db, quiz_id: i32, question_idx: i32) -> Result<Markup, Rejection> {
        let quiz_name = db.quiz_name(quiz_id).await.map_err(|e| {
            tracing::error!("could not get quiz name for quiz={quiz_id}: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        let question_id = db
            .question_id_from_idx(quiz_id, question_idx)
            .await
            .map_err(|e| {
                tracing::error!(
                "could not get question id for question_idx={question_idx} on quiz={quiz_id}: {e}"
            );
                warp::reject::custom(InternalServerError)
            })?;

        let question = db.get_question(question_id).await.map_err(|e| {
            tracing::error!("could not get question with id={question_id}: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        let questions_count = db.questions_count(quiz_id).await.map_err(|e| {
            tracing::error!("could not get question cout for quiz_id={quiz_id}: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        Ok(html! {
            p { "You are doing the quiz " mark { (quiz_name) } "." }
            article style="width: fit-content;" {
                h3 { (question.question) }
                p { "Question " (question_idx + 1) " of " (questions_count) "."  }

                form hx-post=(names::SUBMIT_ANSWER_URL)
                     hx-ext="json-enc"
                     hx-target="main"
                     hx-disabled-elt="find input[type='radio'], find input[type='submit']"
                     hx-swap="innerHTML" {
                    fieldset {
                        @for option in question.options {
                            label {
                                input type="radio" name="option" value=(option.id);
                                (option.option)
                            }
                        }
                    }
                    input type="submit" value="Submit" style="width: fit-content;";
                }
            }
        })
    }

    pub async fn answer(
        db: &Db,
        quiz_id: i32,
        question_idx: i32,
        selected: i32,
    ) -> Result<Markup, Rejection> {
        let quiz_name = db.quiz_name(quiz_id).await.map_err(|e| {
            tracing::error!("could not get quiz name for quiz={quiz_id}: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        let question_id = db
            .question_id_from_idx(quiz_id, question_idx)
            .await
            .map_err(|e| {
                tracing::error!(
                "could not get question id for question_idx={question_idx} on quiz={quiz_id}: {e}"
            );
                warp::reject::custom(InternalServerError)
            })?;

        let question = db.get_question(question_id).await.map_err(|e| {
            tracing::error!("could not get question with id={question_id}: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        let questions_count = db.questions_count(quiz_id).await.map_err(|e| {
            tracing::error!("could not get question cout for quiz_id={quiz_id}: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        let is_final = question_idx + 1 == questions_count;

        Ok(html! {
            p { "You are doing the quiz " mark { (quiz_name) } "." }
            article style="width: fit-content;" {
                h3 { (question.question) }
                p { "Question " (question_idx + 1) " of " (questions_count) "."  }

                form {
                    fieldset disabled="true" {
                        @for option in question.options {
                            label {
                                @if selected == option.id {
                                    input type="radio" name="option" value=(option.id) checked;
                                } @else {
                                    input type="radio" name="option" value=(option.id);
                                }
                                (option.option) " "
                                @if option.is_answer { mark { "answer" } }
                            }
                        }
                    }
                }

                button hx-get=(names::quiz_page_url(quiz_id)) hx-target="main" hx-disabled-elt="this" {
                    @if is_final { "Finish" } @else { "Next" }
                }
            }
        })
    }

    pub async fn page(db: &Db, quiz_id: i32) -> Result<Markup, Rejection> {
        let quiz_name = db.quiz_name(quiz_id).await.map_err(|e| {
            tracing::error!("could not get quiz name for {quiz_id}: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        Ok(html! {
            h1 { "Welcome to Quizzy!" }
            p {
                "You are going to be doing the quiz "
                mark { (quiz_name) }
                ", but before you get started we need "
                strong { "your name" }
                " to identify you."
            }
            article style="width: fit-content;" {
                form hx-post=(names::start_submission_url(quiz_id))
                     hx-ext="json-enc"
                     hx-target="main"
                     hx-disabled-elt="find input[type='text'], find input[type='submit']"
                     hx-swap="innerHTML" {
                    label {
                        "Your Name"
                        input name="name"
                              type="text"
                              autocomplete="off"
                              placeholder="Your Name"
                              aria-describedby="name-helper"
                              aria-label="Your Name";
                        small id="name-helper" { "The quiz admin will be able to see your name." }
                    }
                    input type="submit" value="Get Started";
                }
            }
        })
    }

    pub async fn dashboard(db: &Db, quiz_id: i32) -> Result<Markup, Rejection> {
        let quiz_name = db.quiz_name(quiz_id).await.map_err(|e| {
            tracing::error!("could not get quiz name from database: {e}");
            warp::reject::custom(InternalServerError)
        })?;

        Ok(html! {
            h1 { (quiz_name) }
            p { "Dashboard for quiz number " (quiz_id) "." }
            article style="width: fit-content;" {
                h4 { "Share this link to people so that they can do the quiz." }
                p id="url" { "" }
                script {
                    "document.querySelector('#url').textContent = `${window.location.origin}/quiz/" (quiz_id) "`;"
                }
            }
        })
    }
}

mod names {
    pub const LOGIN_URL: &str = "/login";
    pub const GET_STARTED_URL: &str = "/start";
    pub const CREATE_QUIZ_URL: &str = "/create-quiz";
    pub const SUBMIT_ANSWER_URL: &str = "/submit-answer";

    pub const SESSION_COOKIE_NAME: &str = "session_id";
    pub const SUBMISSION_COOKIE_NAME: &str = "submission";

    pub fn quiz_dashboard_url(quiz_id: i32) -> String {
        format!("/quiz/{quiz_id}/dashboard")
    }

    pub fn quiz_page_url(quiz_id: i32) -> String {
        format!("/quiz/{quiz_id}")
    }

    pub fn delete_quiz_url(quiz_id: i32) -> String {
        format!("/delete-quiz/{quiz_id}")
    }

    pub fn start_submission_url(quiz_id: i32) -> String {
        format!("/start-submission/{quiz_id}")
    }
}

mod utils {
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");

    pub fn cookie(name: &str, value: &str) -> String {
        format!("{name}={value}; HttpOnly; Max-Age=3600; Secure; Path=/; SameSite=Strict")
    }
}

mod model {
    use serde::Deserialize;

    pub type Questions = Vec<Question>;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Question {
        pub question: String,
        pub options: Vec<QuestionOption>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct QuestionOption {
        pub text: String,
        pub is_answer: bool,
    }
}

mod rejections {
    use std::convert::Infallible;

    use maud::{html, Markup};
    use warp::{
        http::StatusCode,
        reject::{Reject, Rejection},
        reply::Reply,
    };

    use crate::views;

    macro_rules! rejects {
        ($($name:ident),*) => {
            $(
                #[derive(Debug)]
                pub struct $name;

                impl Reject for $name {}
            )*
        };
    }

    rejects!(InternalServerError, Unauthorized, InputError);

    pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
        let code;
        let message;

        if err.is_not_found() {
            code = StatusCode::NOT_FOUND;
            message = "NOT_FOUND";
        } else if err
            .find::<warp::filters::body::BodyDeserializeError>()
            .is_some()
        {
            code = StatusCode::BAD_REQUEST;
            message = "BAD_REQUEST";
        } else if let Some(InternalServerError) = err.find() {
            code = StatusCode::INTERNAL_SERVER_ERROR;
            message = "INTERNAL_SERVER_ERROR";
        } else if let Some(Unauthorized) = err.find() {
            code = StatusCode::UNAUTHORIZED;
            message = "UNAUTHORIZED";
        } else if let Some(InputError) = err.find() {
            code = StatusCode::BAD_REQUEST;
            message = "INPUT_ERROR";
        } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
            code = StatusCode::METHOD_NOT_ALLOWED;
            message = "METHOD_NOT_ALLOWED";
        } else if err
            .find::<warp::reject::InvalidHeader>()
            .is_some_and(|e| e.name() == warp::http::header::COOKIE)
        {
            code = StatusCode::BAD_REQUEST;
            message = "COOKIE_NOT_AVAILABLE";
        } else {
            tracing::error!("unhandled rejection: {:?}", err);
            code = StatusCode::INTERNAL_SERVER_ERROR;
            message = "UNHANDLED_REJECTION";
        }

        Ok(warp::reply::with_status(error_page(message), code))
    }

    fn error_page(message: &str) -> Markup {
        views::page(
            "Error",
            html! {
                h1 { (message) }
            },
        )
    }
}
