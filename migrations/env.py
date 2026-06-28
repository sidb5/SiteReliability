import sys
import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

alembic_config = context.config

if alembic_config.config_file_name is not None:
    fileConfig(alembic_config.config_file_name)

# Override URL from application config only when the caller has not already
# provided one (i.e., the URL is still the alembic.ini default).
# Tests call cfg.set_main_option("sqlalchemy.url", test_url) before upgrade(),
# so we must not clobber that value with settings.DATABASE_URL here.
_ALEMBIC_INI_DEFAULT_URL = "sqlite:///./watchdog.db"
_current_url = alembic_config.get_main_option("sqlalchemy.url")
if _current_url == _ALEMBIC_INI_DEFAULT_URL:
    try:
        from config import settings
        alembic_config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
    except Exception:
        pass

# Import Base for autogeneration support; ORM models accumulate here as modules are built
try:
    from database import Base  # noqa: F401 — models register themselves on import
    import models.db  # noqa: F401 — ensure all ORM models are registered on Base
    target_metadata = Base.metadata
except Exception:
    target_metadata = None


def run_migrations_offline() -> None:
    url = alembic_config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        alembic_config.get_section(alembic_config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
