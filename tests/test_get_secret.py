"""Tests for _get_secret method handling of newer API responses."""

import unittest

from passboltapi.schema import PassboltSecretTuple, constructor


class TestSecretConstructor(unittest.TestCase):
    """Test that constructor() properly filters extra fields from API responses."""

    def test_constructor_filters_extra_fields(self):
        """
        Newer Passbolt API versions return extra fields like 'secret_revision_id'
        in the /secrets/resource/{id}.json response. The constructor should filter
        these out to avoid TypeError when constructing PassboltSecretTuple.
        """
        # Simulate API response with extra field (secret_revision_id)
        api_response_body = {
            "id": "abc123",
            "user_id": "user456",
            "resource_id": "resource789",
            "data": "encrypted_data_here",
            "created": "2024-01-01T00:00:00+00:00",
            "modified": "2024-01-02T00:00:00+00:00",
            "secret_revision_id": "rev999",  # Extra field from newer API
        }

        # Use constructor with default filter_fields=True
        secret = constructor(PassboltSecretTuple)(api_response_body)

        # Verify the tuple was created correctly
        self.assertEqual(secret.id, "abc123")
        self.assertEqual(secret.user_id, "user456")
        self.assertEqual(secret.resource_id, "resource789")
        self.assertEqual(secret.data, "encrypted_data_here")
        self.assertEqual(secret.created, "2024-01-01T00:00:00+00:00")
        self.assertEqual(secret.modified, "2024-01-02T00:00:00+00:00")

    def test_constructor_without_extra_fields_still_works(self):
        """Ensure constructor works normally without extra fields."""
        api_response_body = {
            "id": "abc123",
            "user_id": "user456",
            "resource_id": "resource789",
            "data": "encrypted_data_here",
            "created": "2024-01-01T00:00:00+00:00",
            "modified": "2024-01-02T00:00:00+00:00",
        }

        secret = constructor(PassboltSecretTuple)(api_response_body)

        self.assertEqual(secret.id, "abc123")
        self.assertEqual(secret.data, "encrypted_data_here")

    def test_constructor_with_filter_disabled_raises_error(self):
        """Demonstrate that with filter_fields=False, extra fields cause TypeError."""
        api_response_body = {
            "id": "abc123",
            "user_id": "user456",
            "resource_id": "resource789",
            "data": "encrypted_data_here",
            "created": "2024-01-01T00:00:00+00:00",
            "modified": "2024-01-02T00:00:00+00:00",
            "secret_revision_id": "rev999",  # Extra field
        }

        with self.assertRaises(TypeError) as context:
            constructor(PassboltSecretTuple, filter_fields=False)(api_response_body)

        self.assertIn("secret_revision_id", str(context.exception))

    def test_constructor_handles_list_of_secrets(self):
        """Ensure constructor handles list input correctly."""
        api_response_list = [
            {
                "id": "abc123",
                "user_id": "user456",
                "resource_id": "resource789",
                "data": "encrypted_data_1",
                "created": "2024-01-01T00:00:00+00:00",
                "modified": "2024-01-02T00:00:00+00:00",
                "secret_revision_id": "rev999",
            },
            {
                "id": "def456",
                "user_id": "user789",
                "resource_id": "resource012",
                "data": "encrypted_data_2",
                "created": "2024-01-03T00:00:00+00:00",
                "modified": "2024-01-04T00:00:00+00:00",
                "secret_revision_id": "rev888",
            },
        ]

        secrets = constructor(PassboltSecretTuple)(api_response_list)

        self.assertEqual(len(secrets), 2)
        self.assertEqual(secrets[0].id, "abc123")
        self.assertEqual(secrets[1].id, "def456")


if __name__ == "__main__":
    unittest.main()
