from django.test import TestCase

# Create your tests here.
from django.test import TestCase, Client
from django.urls import reverse
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.messages import get_messages
from accounts.models import CustomUser  # Importe o modelo CustomUser

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.messages import get_messages
from accounts.models import CustomUser  # Modelo personalizado

# Cliente HTTP para simular requisições
client = Client()

# Classe para testes de criação de usuário
class UserCreationTests(TestCase):
    def setUp(self):
        self.register_url = reverse("register")

    def test_username_already_exists(self):
        """Testa a criação de usuário com nome de usuário duplicado."""
        CustomUser.objects.create_user(username="usuario_existente", email="email_novo@example.com", password="senha123")
        response = client.post(self.register_url, {
            "username": "usuario_existente",
            "email": "email_novo2@example.com",
            "password1": "senha123",
            "password2": "senha123"
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("Usuário já existe", str(messages[0]))

    def test_email_already_exists(self):
        """Testa a criação de usuário com e-mail duplicado."""
        CustomUser.objects.create_user(username="usuario_novo", email="email_existente@example.com", password="senha123")
        response = client.post(self.register_url, {
            "username": "usuario_novo2",
            "email": "email_existente@example.com",
            "password1": "senha123",
            "password2": "senha123"
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("Email já cadastrado", str(messages[0]))

    def test_passwords_do_not_match(self):
        """Testa a criação de usuário com senhas não coincidentes."""
        response = client.post(self.register_url, {
            "username": "usuario_teste",
            "email": "usuario_teste@example.com",
            "password1": "senha123",
            "password2": "senha456"
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("As senhas não coincidem", str(messages[0]))

    def test_required_fields(self):
        """Testa a criação de usuário com campos obrigatórios em branco."""
        response = client.post(self.register_url, {})
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("O campo Usuário é obrigatório", str(messages[0]))
        self.assertIn("O campo E-mail é obrigatório", str(messages[1]))
        self.assertIn("O campo Senha é obrigatório", str(messages[2]))

    def test_weak_password(self):
        """Testa a criação de usuário com senha fraca."""
        response = client.post(self.register_url, {
            "username": "usuario_teste",
            "email": "usuario_teste@example.com",
            "password1": "a",
            "password2": "a"
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("A senha deve conter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais", str(messages[0]))


# Classe para testes de login
class LoginTests(TestCase):
    def setUp(self):
        self.login_url = reverse("login")
        self.user = CustomUser.objects.create_user(username="usuario_teste", email="usuario_teste@example.com", password="senha123")

    def test_login_valid_credentials(self):
        """Testa o login com credenciais válidas."""
        response = client.post(self.login_url, {
            "username": "usuario_teste",
            "password": "senha123"
        })
        self.assertRedirects(response, reverse("dashboard"))

    def test_login_invalid_password(self):
        """Testa o login com senha incorreta."""
        response = client.post(self.login_url, {
            "username": "usuario_teste",
            "password": "senhaerrada"
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("Senha incorreta", str(messages[0]))

    def test_login_missing_fields(self):
        """Testa o login com campos obrigatórios em branco."""
        response = client.post(self.login_url, {})
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("O campo Usuário é obrigatório", str(messages[0]))
        self.assertIn("O campo Senha é obrigatório", str(messages[1]))

    def test_login_invalid_user_and_password(self):
        """Testa o login com usuário inválido e senha incorreta."""
        response = client.post(self.login_url, {
            "username": "usuario_invalido",
            "password": "senhaerrada"
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("Usuário ou senha inválidos", str(messages[0]))

    def test_login_invalid_user_valid_password(self):
        """Testa o login com usuário em branco e senha correta."""
        response = client.post(self.login_url, {
            "username": "",
            "password": "senha123"
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("O campo Usuário é obrigatório", str(messages[0]))

    def test_login_valid_user_invalid_password(self):
        """Testa o login com usuário válido e senha incorreta."""
        response = client.post(self.login_url, {
            "username": "usuario_teste",
            "password": "senhaerrada"
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("Senha incorreta", str(messages[0]))

    def test_login_valid_user_blank_password(self):
        """Testa o login com usuário válido e senha em branco."""
        response = client.post(self.login_url, {
            "username": "usuario_teste",
            "password": ""
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("O campo Senha é obrigatório", str(messages[0]))

    def test_login_blank_fields(self):
        """Testa o login com os dois campos em branco."""
        response = client.post(self.login_url, {
            "username": "",
            "password": ""
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("O campo Usuário é obrigatório", str(messages[0]))
        self.assertIn("O campo Senha é obrigatório", str(messages[1]))


# Classe para testes de recuperação de senha
class PasswordRecoveryTests(TestCase):
    def setUp(self):
        self.forget_password_url = reverse("forget_password")
        self.user = CustomUser.objects.create_user(username="usuario_teste", email="usuario_teste@example.com", password="senha123")

    def test_password_recovery_valid_email(self):
        """Testa a recuperação de senha com e-mail válido."""
        response = client.post(self.forget_password_url, {
            "email": "usuario_teste@example.com"
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("Email de recuperação enviado!", str(messages[0]))

    def test_password_recovery_invalid_email(self):
        """Testa a recuperação de senha com e-mail inválido."""
        response = client.post(self.forget_password_url, {
            "email": "email_invalido@example.com"
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("Este e-mail não está cadastrado no sistema. Por favor, realize o cadastro", str(messages[0]))

    def test_password_recovery_blank_email(self):
        """Testa a recuperação de senha com campo de e-mail em branco."""
        response = client.post(self.forget_password_url, {
            "email": ""
        })
        messages = list(get_messages(response.wsgi_request))
        self.assertIn("Preencha o campo com o e-mail cadastrado", str(messages[0]))