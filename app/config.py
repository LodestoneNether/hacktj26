from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    database_url: str = 'postgresql+psycopg2://postgres:postgres@localhost:5432/osint'
    neo4j_uri: str = 'bolt://localhost:7687'
    neo4j_user: str = 'neo4j'
    neo4j_password: str = 'password'

    secret_key: str = 'change-me'
    algorithm: str = 'HS256'
    access_token_minutes: int = 60

    # Default to local no-infra Celery transport so worker can start without Redis.
    celery_broker_url: str = 'memory://'
    celery_result_backend: str = 'cache+memory://'
    celery_task_always_eager: bool = True

    osint_http_timeout_s: float = 1.5
    osint_max_usernames_per_case: int = 20
    osint_max_emails_per_case: int = 20
    use_torch_embeddings: bool = False

    default_admin_email: str = 'admin@local'
    default_admin_password: str = 'admin123'


settings = Settings()
