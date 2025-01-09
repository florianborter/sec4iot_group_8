import sys
from colorama import init
from internal.card import VendingMachineCard, Logger

init()

if len(sys.argv) < 2:
    print(f"Usage: python3 cipher.py <filename> [-v]")
    exit()

filename = sys.argv[1]

if "-v" in sys.argv:
    Logger.log_verbose = True

# Initialize the card
card = VendingMachineCard.init_card()

# Authenticate before signing or verifying
while True:
    try:
        pin = input("PIN? (default is 1234): ")
        if not pin.strip():  # Use the default PIN if none is provided
            pin = "1234"
        print("Authentification...")
        card.login(pin)  # Attempt authentication
        print("Authentification réussie.")
        break
    except Exception as e:
        print(f"Authentication failed: {e}")
        if "blocked" in str(e).lower():
            reset = input("The card is blocked. Reset it? (y/N): ").strip().lower()
            if reset == "y":
                card.factory_reset()
            else:
                exit()

if filename.endswith(".sign"):
    print("Verifying signature...")
    try:
        # Read the original data
        original_filename = filename[:-5]  # Remove `.sign` extension
        with open(original_filename, "rb") as f:
            original_data = f.read()

        # Read the signature
        with open(filename, "rb") as f:
            signature = f.read()

        # Verify the signature
        result = card.verify_signature(original_data, signature)
        print(result)
    except Exception as e:
        print(f"Verification failed: {e}")
else:
    print("Signature du fichier...")
    try:
        # Read the file data
        with open(filename, "rb") as f:
            data = f.read()

        # Sign the data
        signature = card.sign_data(data)
        with open(filename + ".sign", "wb") as f:
            f.write(signature)
        print("Fichier signé.")
    except Exception as e:
        print(f"Signing failed: {e}")
