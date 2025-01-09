import sys
from colorama import init
from internal.card import VendingMachineCard, Logger

init()

if "-v" in sys.argv:
    Logger.log_verbose = True

# Initialiser la carte
card = VendingMachineCard.init_card()

print("\nInterface REPL de la carte activée. Tapez 'aide' pour une liste des commandes disponibles.\n")

# Définir les commandes
commands = {
    "connexion": {
        "func": card.login,
        "args": ["pin"],
        "help": "Authentifiez-vous avec le code PIN fourni."
    },
    "deconnexion": {
        "func": card.logout,
        "args": [],
        "help": "Déconnectez la session actuelle authentifiée."
    },
    "changer_pin": {
        "func": card.change_pin,
        "args": ["nouveau_pin"],
        "help": "Changez le code PIN. Vous devrez vous reconnecter après cela."
    },
    "signer": {
        "func": card.sign_data,
        "args": ["données"],
        "help": "Signez les données fournies avec la clé privée de la carte. Utilisez des guillemets pour les données contenant des espaces."
    },
    "verifier": {
        "func": card.verify_signature,
        "args": ["données"],
        "help": "Vérifiez la signature des données fournies avec la clé publique. La signature est automatiquement lue depuis 'signature.bin'."
    },
    "reinitialiser": {
        "func": card.factory_reset,
        "args": [],
        "help": "Réinitialisez la carte à son état d'usine."
    },
    "obtenir_cle_publique": {
        "func": card.get_public_key,
        "args": [],
        "help": "Récupérez la clé publique de la carte."
    },
    "obtenir_cle_privee": {
        "func": card.get_private_key,
        "args": [],
        "help": "Récupérez la clé privée de la carte. Nécessite une authentification."
    },
    "charger_cle": {
        "func": card.load_public_key,
        "args": [],
        "help": "Chargez la clé publique depuis un fichier."
    },
    "sauvegarder_cle": {
        "func": card.save_public_key,
        "args": [],
        "help": "Sauvegardez la clé publique dans un fichier."
    },
    "aide": {
        "func": None,
        "args": [],
        "help": "Affichez ce message d'aide."
    },
    "quitter": {
        "func": None,
        "args": [],
        "help": "Quittez l'interface REPL."
    }
}

# Boucle REPL
while True:
    try:
        # Lire l'entrée utilisateur
        cmd_input = input("> ").strip()
        if not cmd_input:
            continue

        # Séparer la commande et les arguments
        parts = cmd_input.split(maxsplit=1)
        cmd_name = parts[0]
        cmd_args = parts[1:] if len(parts) > 1 else []

        if cmd_name == "aide":
            print("\nCommandes disponibles :")
            for name, details in commands.items():
                print(f"  {name} {' '.join(f'<{arg}>' for arg in details['args'])}")
                print(f"    {details['help']}")
            print()
            continue

        if cmd_name == "quitter":
            print("Fermeture...")
            break

        if cmd_name not in commands:
            print(f"Commande inconnue : {cmd_name}")
            continue

        # Récupérer les détails de la commande
        cmd_details = commands[cmd_name]
        func = cmd_details["func"]
        args = cmd_details["args"]

        # Séparer les arguments si fournis
        if cmd_args:
            cmd_args = cmd_args[0].split(maxsplit=len(args) - 1)

        # Valider le nombre d'arguments
        if len(cmd_args) != len(args):
            print(f"Usage : {cmd_name} {' '.join(f'<{arg}>' for arg in args)}")
            continue

        # Gérer les commandes spécifiques
        if cmd_name == "signer":
            cmd_args[0] = cmd_args[0].encode("utf-8")  # Convertir en bytes
            signature = func(*cmd_args)
            with open("signature.bin", "wb") as f:
                f.write(signature)  # Sauvegarder la signature en bytes
            print("Signature sauvegardée dans 'signature.bin'. Utilisez ce fichier pour la vérification.")

        elif cmd_name == "verifier":
            try:
                with open("signature.bin", "rb") as f:
                    signature = f.read()  # Charger la signature en bytes
                cmd_args[0] = cmd_args[0].encode("utf-8")  # Convertir en bytes
                result = func(cmd_args[0], signature)  # Passer les données et la signature
                print(result)
            except FileNotFoundError:
                print("Erreur : Le fichier de signature ('signature.bin') est manquant. Veuillez d'abord signer des données.")
            except Exception as e:
                print(f"Erreur : {e}")

        elif cmd_name == "changer_pin":
            func(*cmd_args)
            card.save_pin()  
            print("= Note : vous devrez vous reconnecter après cela")

        elif cmd_name == "reinitialiser":
            result = func()
            card.save_pin() 
            print(result)
            print("= Note : vous devrez vous reconnecter après cela")

        elif cmd_name in ["obtenir_cle_publique", "obtenir_cle_privee"]:
            result = func()
            print(result)

        else:

            result = func(*cmd_args)
            print(result if result is not None else "Commande exécutée avec succès.")
    except Exception as e:
        print(f"Erreur : {e}")
