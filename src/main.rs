use warp::Filter;
use tera::Tera;
use std::sync::Arc;
use tokio::sync::watch; // Optional: For graceful shutdown

mod handlers;
mod jwks;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    // Fetch JWKS before starting the server
    jwks::fetch_jwks().await.expect("Failed to fetch JWKS");

    // Start the JWKS refresh task in the background
    tokio::spawn(jwks::start_jwks_refresh());

    // Optional: If you want to add graceful shutdown support
    // let (shutdown_tx, shutdown_rx) = watch::channel(());
    // tokio::spawn(jwks::start_jwks_refresh_with_shutdown(shutdown_rx));

    // Initialize Tera templates
    let tera = Arc::new(Tera::new("html/**/*").expect("Failed to compile templates"));

    // Serve static files from the "html" directory
    let static_files = warp::path("static")
        .and(warp::fs::dir("html"));

    // Serve the index.html file at the root path
    let index = warp::path::end()
        .and(warp::fs::file("html/index.html"));

    // Define the login route
    let login = warp::path("login")
        .and(warp::get())
        .and_then(handlers::login_handler);

    // Define the callback route
    let callback = warp::path("callback")
        .and(warp::get())
        .and(warp::query::<handlers::CallbackQuery>())
        .and(handlers::with_tera(tera.clone()))
        .and_then(handlers::callback_handler);

    // Combine all routes
    let routes = index
        .or(login)
        .or(callback)
        .or(static_files)
        .with(warp::cors().allow_any_origin());

    // Start the server
    warp::serve(routes)
        .run(([127, 0, 0, 1], 8080))
        .await;

    // Optional: If using graceful shutdown, send the shutdown signal
    // let _ = shutdown_tx.send(());
}