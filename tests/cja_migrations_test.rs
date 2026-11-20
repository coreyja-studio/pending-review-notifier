#[sqlx::test]
async fn app_migrations_cover_cja_migrations(pool: sqlx::PgPool) -> cja::Result<()> {
    sqlx::migrate!().run(&pool).await?;
    let before = sqlx::query_scalar::<_, i64>(
        "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version",
    )
    .fetch_all(&pool)
    .await?;
    cja::db::run_migrations(&pool).await?;
    let after = sqlx::query_scalar::<_, i64>(
        "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(after, before);
    Ok(())
}
