import pytest
from sqlalchemy.exc import IntegrityError
from app import app
from models import db, User

class TestUser:
    """Tests for the User model."""

    def test_has_attributes(self):
        """User has attributes username, password_hash, bio, and image_url."""
        with app.app_context():
            User.query.delete()
            db.session.commit()

            user = User(
                username="ashketchum",
                bio="I wanna be the very best",
                image_url="https://example.com/ash.jpg"
            )
            user.password_hash = "pikachu"
            db.session.add(user)
            db.session.commit()

            new_user = User.query.filter(User.username == "ashketchum").first()
            assert new_user.username == "ashketchum"
            assert new_user.authenticate("pikachu")
            assert new_user.bio == "I wanna be the very best"
            assert new_user.image_url == "https://example.com/ash.jpg"

    def test_requires_username(self):
        """User must have a username."""
        with app.app_context():
            User.query.delete()
            db.session.commit()

            user = User()
            with pytest.raises(IntegrityError):
                db.session.add(user)
                db.session.commit()
