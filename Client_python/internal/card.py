import hashlib
from smartcard.System import readers
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


class Logger:
    log_verbose = False

    @staticmethod
    def log(*msg):
        if Logger.log_verbose:
            print(*msg)


class VendingMachineCard:
    def __init__(self, connection):
        self.connection = connection
        self.private_key = None
        self.public_key = None
        self.pin = "1234"
        self.authenticated = False
        self.load_pin()

    @staticmethod
    def init_card():
        for reader in readers():
            try:
                connection = reader.createConnection()
                connection.connect()
                print(f"Connecté à : {reader}")
                return VendingMachineCard(connection)
            except Exception as e:
                print(f"Erreur lors de la connexion à la carte : {e}")
        raise Exception("Aucun lecteur de carte trouvé.")

    def login(self, pin):
        if pin == self.pin:
            self.authenticated = True
            return "Connexion réussie."
        self.authenticated = False
        raise Exception("PIN invalide ou carte bloquée.")

    def logout(self):
        self.authenticated = False
        return "Déconnexion réussie."

    def change_pin(self, new_pin: str):
        if len(new_pin) != 4 or not new_pin.isdigit():
            raise ValueError("Le PIN doit comporter exactement 4 chiffres.")
        self.pin = new_pin
        self.save_pin()
        print("= Remarque : vous devrez vous reconnecter après cela")
        return "PIN modifié avec succès."

    def factory_reset(self):
        self.pin = "1234"
        self.save_pin()
        self.private_key = None
        self.public_key = None
        self.authenticated = False
        print("= Remarque : vous devrez vous reconnecter après cela")
        return "La carte a été réinitialisée à ses paramètres d'usine."

    def save_pin(self):
        with open("pin.txt", "w") as f:
            f.write(self.pin)
        print("PIN enregistré avec succès.")

    def load_pin(self):
        try:
            with open("pin.txt", "r") as f:
                self.pin = f.read().strip()
            print("PIN chargé avec succès.")
        except FileNotFoundError:
            self.pin = "1234"
            print("Aucun fichier PIN trouvé. Utilisation du PIN par défaut : 1234.")

    def generate_keys(self):
        key = RSA.generate(2048)
        self.private_key = key
        self.public_key = key.publickey()

    def save_public_key(self, filename="public_key.pem"):
        if self.public_key is None:
            raise Exception("Clé publique non disponible. Générez une paire de clés d'abord.")
        with open(filename, "wb") as f:
            f.write(self.public_key.export_key())
        print(f"Clé publique enregistrée dans {filename}")

    def load_public_key(self, filename="public_key.pem"):
        try:
            with open(filename, "rb") as f:
                self.public_key = RSA.import_key(f.read())
            print(f"Clé publique chargée depuis {filename}")
        except FileNotFoundError:
            raise Exception("Fichier de clé publique introuvable. Veuillez signer des données d'abord.")

    def get_public_key(self):
        if self.public_key is None:
            self.generate_keys()
            self.save_public_key()
        return self.public_key

    def get_private_key(self):
        if not self.authenticated:
            raise Exception("Condition de sécurité non satisfaite. Veuillez vous authentifier d'abord.")
        if self.private_key is None:
            self.generate_keys()
        return self.private_key.n, self.private_key.e, self.private_key.d, self.private_key.p, self.private_key.q

    def sign_data(self, data):
        if self.private_key is None:
            self.generate_keys()
            self.save_public_key()

        hashed_data = SHA256.new(data)
        signature = pkcs1_15.new(self.private_key).sign(hashed_data)
        return signature

    def verify_signature(self, data, signature):
        if self.public_key is None:
            self.load_public_key()

        hashed_data = SHA256.new(data)
        try:
            pkcs1_15.new(self.public_key).verify(hashed_data, signature)
            return "La signature est valide."
        except (ValueError, TypeError):
            return "La signature est invalide."
