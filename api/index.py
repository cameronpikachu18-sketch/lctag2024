import base64
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

# ==========================================
# CONFIGURATION
# ==========================================
PackageName = "com.visonfortop1"
Cert = "0CBD8BA08218D2F5A7FBE2820534F670F9C396199620845557185460D06B2D76"

# ==========================================
# ROUTES
# ==========================================

@app.route("/", methods=["POST", "GET"])
def main():
    return "If the link doesnt work this will not popup."

@app.route("/api/authenticate/attestation/mothershipAuth", methods=["POST"])
def mothership_auth():
    try:
        data = request.get_json()
        if not data or "nonce_token" not in data:
            return jsonify({"BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Missing token."}), 400

        nonce_token = data["nonce_token"]

        # Meta Quest attestation tokens typically consist of a header, payload, and signature split by '.'
        parts = nonce_token.split('.')
        if len(parts) < 2:
            return jsonify({"BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Invalid token format."}), 400

        # Decode the payload part (usually the second part)
        payload_b64 = parts[1]
        
        # Add padding if necessary for base64 decoding
        payload_b64 += '=' * (-len(payload_b64) % 4)
        decoded_bytes = base64.b64decode(payload_b64)
        payload = json.loads(decoded_bytes.decode('utf-8'))

        # Extract the attestation parameters from Meta's token structure
        # (Adjust keys according to your specific token payload structure if needed)
        sha256_sig = payload.get("package_project_hash") or payload.get("Sha256Sig") or ""
        store_recognized = payload.get("store_recognized") or payload.get("StoreRecognized") or ""
        token_package = payload.get("package_name") or payload.get("PackageName") or ""

        # 1. Package Name Validation
        if token_package != PackageName:
            return jsonify({"BanMessage": f"OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Package name mismatch. Expected {PackageName}."}), 403

        # 2. Certificate Fingerprint Validation
        if not sha256_sig or Cert not in sha256_sig.upper():
            return jsonify({"BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Unrecognized package certificate fingerprint."}), 403

        # 3. App Distribution Channel Validation
        if store_recognized != "StoreRecognized":
            return jsonify({"BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Unrecognized application distribution director channel source."}), 403

        # Everything passed successfully
        return jsonify({
            "status": "success",
            "message": "Integrity check passed successfully."
        }), 200

    except Exception as e:
        return jsonify({"BanMessage": f"INTERNAL SERVER ERROR: {str(e)}"}), 500


@app.route("/api/PlayFabAuthentication", methods=["POST"])
def playfab_authentication():
    try:
        data = request.get_json()
        # Your custom server side PlayFab authentication/webhook logic goes here
        
        return jsonify({
            "status": "success",
            "message": "PlayFab authentication endpoint reached."
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
