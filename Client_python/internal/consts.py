# Import colors for pretty printing

# CLA for the project
CLA_PROJET = 0x42

# Applet AID (Application Identifier)
APPLET_AID = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01, 0x02]


# Status Words (SW)
SW_COMMAND_SUCCESS = 0x9000
SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982
SW_BLOCKED = 0x6983

# Instruction (INS) codes
INS_HELLO = 0x01  # Get a greeting from the card
INS_LOGIN = 0x02  # Login with PIN
INS_CHANGE_PIN = 0x03  # Change the PIN
INS_LOGOUT = 0x04  # Logout from the card
INS_FACTORY_RESET = 0x05  # Reset the card to factory state
INS_SIGN = 0x06  # Sign data using SHA-256
INS_GET_PUBLIC_KEY = 0x07  # Retrieve the public key from the card
INS_GET_PRIVATE_KEY = 0x08  # Retrieve the private key (requires auth)
INS_LOAD = 0xE8  # Load applet
INS_SELECT = 0xA4  # Select applet
INS_VERIFY_PIN = 0x20

# Helper function to map instruction codes to names
def get_instruction_name(ins):
    """
    Return the instruction name corresponding to the given INS code.
    
    Example:
        get_instruction_name(0x01) -> "HELLO"
        get_instruction_name(0xFF) -> "FF" (unknown instruction)
    """
    results = [key for key, val in globals().items() if val == ins and key.startswith("INS_")]
    if results:
        return results[0][4:]  # Remove the "INS_" prefix
    return f"{ins:02X}"  # Return the hex value if no name found
