import os

import pytest

from app import create_app, db


@pytest.fixture()
def test_client():
    """
    Fixture for setting up a Flaskeddit app, the database tables, and a test client.
    """
    app = create_app(os.getenv('BBS_CONFIG') or 'default')
    app.app_context().push()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
    app.config["WTF_CSRF_ENABLED"] = False
    db.create_all()
    yield app.test_client()
    db.drop_all()
