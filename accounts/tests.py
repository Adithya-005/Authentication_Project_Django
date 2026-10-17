from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core import mail
from django.urls import reverse


class PasswordChangeOTPTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="password-user",
            email="password@example.com",
            password="Old!Password923",
        )
        self.client.force_login(self.user)

    def test_password_change_requires_email_otp(self):
        response = self.client.post(
            reverse("update_password"),
            {"action": "send_otp"},
        )

        self.assertRedirects(response, reverse("verify_password_change_otp"))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["password@example.com"])

        otp = mail.outbox[0].body.split("code is ", 1)[1].split(".", 1)[0]
        response = self.client.post(
            reverse("verify_password_change_otp"),
            {"otp": otp},
        )
        self.assertRedirects(response, reverse("update_password"))

        response = self.client.post(
            reverse("update_password"),
            {
                "old_password": "Old!Password923",
                "new_password1": "New!Password924",
                "new_password2": "New!Password924",
            },
        )

        self.assertRedirects(response, reverse("home"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("New!Password924"))

    def test_invalid_otp_does_not_authorize_password_change(self):
        self.client.post(reverse("update_password"), {"action": "send_otp"})
        otp = mail.outbox[0].body.split("code is ", 1)[1].split(".", 1)[0]
        wrong_otp = "000000" if otp != "000000" else "000001"

        response = self.client.post(
            reverse("verify_password_change_otp"),
            {"otp": wrong_otp},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("otp", response.context["form"].errors)
        response = self.client.post(
            reverse("update_password"),
            {
                "old_password": "Old!Password923",
                "new_password1": "New!Password924",
                "new_password2": "New!Password924",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Verify your email address")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Old!Password923"))

    def test_otp_is_invalidated_after_five_wrong_attempts(self):
        self.client.post(reverse("update_password"), {"action": "send_otp"})
        otp = mail.outbox[0].body.split("code is ", 1)[1].split(".", 1)[0]
        wrong_otp = "000000" if otp != "000000" else "000001"

        for _ in range(5):
            response = self.client.post(
                reverse("verify_password_change_otp"),
                {"otp": wrong_otp},
            )

        self.assertContains(response, "Too many incorrect codes")
        response = self.client.post(
            reverse("verify_password_change_otp"),
            {"otp": otp},
        )
        self.assertContains(response, "invalid or expired")

    def test_account_without_email_cannot_request_otp(self):
        self.user.email = ""
        self.user.save(update_fields=["email"])

        response = self.client.post(
            reverse("update_password"),
            {"action": "send_otp"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Your account has no email address.")
        self.assertEqual(len(mail.outbox), 0)


class RegistrationTests(TestCase):
    def test_registration_creates_user_with_email(self):
        response = self.client.post(
            reverse("register"),
            {
                "username": "new-account",
                "email": "new@example.com",
                "password1": "Strong!Pass923",
                "password2": "Strong!Pass923",
            },
        )

        self.assertRedirects(response, reverse("signin"))
        user = get_user_model().objects.get(username="new-account")
        self.assertEqual(user.email, "new@example.com")

    def test_registration_rejects_mismatched_passwords(self):
        response = self.client.post(
            reverse("register"),
            {
                "username": "new-account",
                "email": "new@example.com",
                "password1": "Strong!Pass923",
                "password2": "Different!Pass923",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("password2", response.context["form"].errors)
