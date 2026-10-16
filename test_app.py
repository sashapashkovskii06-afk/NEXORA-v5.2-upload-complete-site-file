"""Smoke tests for the NEXORA Flask application. Run with: python -m unittest discover -s tests"""
import os
import unittest

# Isolated database and predictable test-only settings must be set before app import.
os.environ["APP_ENV"] = "development"
os.environ["SECRET_KEY"] = "test-only-secret-not-for-deployment"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ.pop("OWNER_EMAIL", None)

from app import app, db


class NEXORASmokeTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()
        with app.app_context():
            db.drop_all()
            db.create_all()

    def test_homepage_renders(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"NEXORA", response.data)

    def test_health_endpoint_checks_database(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["database"], "connected")

    def test_profile_requires_login(self):
        response = self.client.get("/api/profile")
        self.assertEqual(response.status_code, 401)

    def test_registration_rejects_invalid_email(self):
        response = self.client.post("/api/auth/register", json={
            "email": "not-an-email", "username": "nexorauser", "password": "long-test-password"
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("email", response.get_json()["error"].lower())

    def test_themes_endpoint_is_available(self):
        response = self.client.get("/api/themes")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["themes"], [])


if __name__ == "__main__":
    unittest.main()
