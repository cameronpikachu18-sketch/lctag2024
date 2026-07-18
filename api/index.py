import base64
import json
import random
import secrets
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request
import requests

class GameInfo:
    def __init__(self):
        self.TitleId: str = ""
        self.SecretKey: str = ""
        self.ApiKey: str = ""

    def GetAuthHeaders(self) -> dict:
        return {
            "content-type": "application/json",
            "X-SecretKey": self.SecretKey
        }

    def GetTitle(self) -> str:
        return self.TitleId

settings: GameInfo = GameInfo()
app: Flask = Flask(__name__)

# Global Caches & Security Variables
playfabCache: dict = {}
muteCache: dict = {}
currentNonces: dict = {}

# Filled Credentials
settings.TitleId = "EB64D"
settings.SecretKey = "N7A51URUTO48XIG583NZDH9WXW8HDZ6FTJ4NN4Q3G8BK3FRDX1"
settings.ApiKey = "OC|1166633403205472|9dde8f0a0f9c8efb2823224de58d2477"

# Attestation Validation Settings (Cleaned & Uppercased)
Valid_Package = "com.monkeytouchers"
Cert = "0CBD8BA08218D2F5A7FBE2820534F670F9C396199620845557185460D06B2D76"

def ReturnFunctionJson(data, funcname, funcparam={}):
    print(f"Calling function: {funcname} with parameters: {funcparam}")
    rjson = data.get("FunctionParameter", {})
    userId = rjson.get("CallerEntityProfile", {}).get("Lineage", {}).get("TitlePlayerAccountId")

    print(f"UserId: {userId}")

    req = requests.post(
        url=f"https://{settings.TitleId}.playfabapi.com/Server/ExecuteCloudScript",
        json={
            "PlayFabId": userId,
            "FunctionName": funcname,
            "FunctionParameter": funcparam
        },
        headers=settings.GetAuthHeaders()
    )

    if req.status_code == 200:
        result = req.json().get("data", {}).get("FunctionResult", {})
        print(f"Function result: {result}")
        return jsonify(result), req.status_code
    else:
        print(f"Function execution failed, status code: {req.status_code}")
        return jsonify({}), req.status_code

def GetIsNonceValid(nonce: str, oculusId: str):
    req = requests.post(
        url=f'https://graph.oculus.com/user_nonce_validate?nonce={nonce}&user_id={oculusId}&access_token={settings.ApiKey}',
        headers={
            "content-type": "application/json"
        }
    )
    return req.json().get("is_valid")

@app.route("/", methods=["POST", "GET"])
def main():
    return "If the link doesnt work this will not popup."

def AttestationAuthentication(AttestationToken):
    url = (
        "https://graph.oculus.com/platform_integrity/verify"
        f"?token={AttestationToken}&access_token={settings.ApiKey}"
    )
    resp = requests.get(url)
    return resp.json()

def VerifyOculusStandards(userId, nonce):
    validate_url = "https://graph.oculus.com/user_nonce_validate"
    validate_payload = {
        "access_token": settings.ApiKey,
        "nonce": nonce,
        "user_id": userId
    }

    try:
        response = requests.post(validate_url, data=validate_payload)
        response.raise_for_status()
        validation_data = response.json()
    except Exception as e:
        return {"is_valid": False, "org_scoped_id": None, "error": str(e)}

    if not validation_data.get("is_valid"):
        return {"is_valid": False, "org_scoped_id": None}

    org_id_url = f"https://graph.oculus.com/{userId}"
    org_id_params = {
        "access_token": settings.ApiKey,
        "fields": "org_scoped_id"
    }

    try:
        org_response = requests.get(org_id_url, params=org_id_params)
        org_response.raise_for_status()
        org_data = org_response.json()
        org_scoped_id = org_data.get("org_scoped_id")
    except Exception as e:
        return {"is_valid": True, "org_scoped_id": None, "error": str(e)}

    return {"is_valid": True, "org_scoped_id": org_scoped_id}

@app.route("/api/authenticate/attestation/getNonce", methods=["POST"])
def GetNonce():
    data = request.get_json()

    user_id = data.get("UserId")
    nonce = data.get("Nonce")

    if not user_id:
        return jsonify({"error": "The user id provided is null, empty or undefined"}), 400

    if not nonce:
        return jsonify({"error": "The nonce provided is null, empty or undefined"}), 400

    verification = VerifyOculusStandards(user_id, nonce)

    if not verification["is_valid"]:
        return jsonify({
            "error": "The user information details provided are invalid and or undefined"
        }), 403

    challengeNonce = secrets.token_urlsafe(16)
    currentNonces[user_id] = challengeNonce

    return jsonify({
        "challenge_nonce": challengeNonce,
        "org_scoped_id": verification["org_scoped_id"]
    })

@app.route("/api/authenticate/attestation/mothershipAuth", methods=["POST"])
def MotherShipAuth():
    rjson = request.get_json()
    user_id = rjson.get("UserId")
    attestation_token = rjson.get("AttestationToken")

    if not attestation_token or attestation_token.strip() == "":
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: The mothership authentication attestation token is null or empty.",
            "BanExpirationTime": "Unknown"
        }), 403

    data = AttestationAuthentication(attestation_token)

    if "data" not in data or len(data["data"]) == 0:
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: The mothership authentication responded with a value less than 1.",
            "BanExpirationTime": "Unknown"
        }), 403

    response_data = data["data"][0]

    if response_data.get("message") == "invalid signature":
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Invalid attestation signature. Check if you are on the latest version.",
            "BanExpirationTime": "Unknown"
        }), 403

    if response_data.get("message") == "token expired":
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Attestation token expired.",
            "BanExpirationTime": "Unknown"
        }), 403

    if response_data.get("message") != "success":
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Invalid token status.",
            "BanExpirationTime": "Unknown"
        }), 403

    claims = response_data.get("claims")
    decoded_bytes = base64.urlsafe_b64decode(claims + "==")
    claims_json = json.loads(decoded_bytes)

    app_state = claims_json.get("app_state", {})
    device_state = claims_json.get("device_state", {})
    device_ban = claims_json.get("device_ban", {})

    unique_id = device_state.get("unique_id") if device_state else None
    device_integrity_state = device_state.get("device_integrity_state") if device_state else None
    StoreRecognized = app_state.get("app_integrity_state") if app_state else None
    packageId = app_state.get("package_id") if app_state else None
    Sha256Sig = app_state.get("package_cert_sha256_digest") if app_state else None
    device_ban_status = device_ban.get("is_banned") if device_ban else False

    if Sha256Sig is None or Cert not in Sha256Sig.upper():
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Unrecognized package certificate fingerprint.",
            "BanExpirationTime": "Unknown"
        }), 403

    if device_ban_status:
        return jsonify({
            "BanMessage": "Your device is currently banned from this application.",
            "BanExpirationTime": device_ban.get("remaining_ban_time", "Unknown")
        }), 403

    if unique_id is None or device_integrity_state is None or StoreRecognized is None or packageId is None or Sha256Sig is None:
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Missing standard integrity verification response attributes.",
            "BanExpirationTime": "Unknown"
        }), 403

    if packageId != Valid_Package:
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Unrecognized Package ID signature structure.",
            "BanExpirationTime": "Unknown"
        }), 403

    if device_integrity_state != "Advanced":
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Device integrity validation state is untrusted.",
            "BanExpirationTime": "Unknown"
        }), 403

    if StoreRecognized != "StoreRecognized":
        return jsonify({
            "BanMessage": "OCULUS INTEGRITY AUTHENTICATION FAILED. REASON: Unrecognized application distribution director channel source.",
            "BanExpirationTime": "Unknown"
        }), 403

    return jsonify({
        "Success!": "OCULUS INTEGRITY AUTHENTICATION PASSED. REASON: Validation successfully completed."
    })

@app.route("/api/PlayFabAuthentication", methods=["POST", "GET"])
def playfabauthentication():
    rjson = request.get_json()

    if rjson.get("CustomId") is None:
        return jsonify({"Message": "Missing CustomId parameter", "Error": "BadRequest-NoCustomId"})
    if rjson.get("Nonce") is None:
        return jsonify({"Message": "Missing Nonce parameter", "Error": "BadRequest-NoNonce"})
    if rjson.get("AppId") is None:
        return jsonify({"Message": "Missing AppId parameter", "Error": "BadRequest-NoAppId"})
    if rjson.get("Platform") is None:
        return jsonify({"Message": "Missing Platform parameter", "Error": "BadRequest-NoPlatform"})
    if rjson.get("OculusId") is None:
        return jsonify({"Message": "Missing OculusId parameter", "Error": "BadRequest-NoOculusId"})

    if rjson.get("AppId") != settings.TitleId:
        return jsonify({"Message": "Request sent for the wrong App ID", "Error": "BadRequest-AppIdMismatch"})
    if not rjson.get("CustomId").startswith("OC") and not rjson.get("CustomId").startswith("PI"):
        return jsonify({"Message": "Bad request", "Error": "BadRequest-No OC or PI Prefix"})

    url = f"https://{settings.TitleId}.playfabapi.com/Server/LoginWithServerCustomId"
    login_request = requests.post(
        url=url,
        json={
            "ServerCustomId": rjson.get("CustomId"),
            "CreateAccount": True
        },
        headers=settings.GetAuthHeaders()
    )
    
    if login_request.status_code == 200:
        data = login_request.json().get("data")
        sessionTicket = data.get("SessionTicket")
        entityToken = data.get("EntityToken").get("EntityToken")
        playFabId = data.get("PlayFabId")
        entityType = data.get("EntityToken").get("Entity").get("Type")
        entityId = data.get("EntityToken").get("Entity").get("Id")

        # Note: Keeps linking active, but uses your server secret header structure safely.
        requests.post(
            url=f"https://{settings.TitleId}.playfabapi.com/Client/LinkCustomID",
            json={
                "ForceLink": True,
                "CustomId": rjson.get("CustomId")
            },
            headers={"content-type": "application/json", "X-Authorization": sessionTicket}
        )

        return jsonify({
            "PlayFabId": playFabId,
            "SessionTicket": sessionTicket,
            "EntityToken": entityToken,
            "EntityId": entityId,
            "EntityType": entityType
        })
    else:
        if login_request.status_code == 403:
            ban_info = login_request.json()
            if ban_info.get('errorCode') == 1002:
                ban_details = ban_info.get('errorDetails', {})
                ban_expiration_key = next(iter(ban_details.keys()), None)
                ban_expiration_list = ban_details.get(ban_expiration_key, [])
                ban_expiration = ban_expiration_list[0] if len(ban_expiration_list) > 0 else "No expiration date provided."
                return jsonify({
                    'BanMessage': ban_expiration_key,
                    'BanExpirationTime': ban_expiration
                }), 403
            else:
                error_message = ban_info.get('errorMessage', 'Forbidden without ban information.')
                return jsonify({
                    'Error': 'PlayFab Error',
                    'Message': error_message
                }), 403
        else:
            error_info = login_request.json()
            error_message = error_info.get('errorMessage', 'An error occurred.')
            return jsonify({
                'Error': 'PlayFab Error',
                'Message': error_message
            }), login_request.status_code
            
@app.route("/api/CachePlayFabId", methods=["POST", "GET"])
def cacheplatfabid():
    rjson = request.get_json()
    playfabCache[rjson.get("PlayFabId")] = rjson
    return jsonify({"Message": "Success"}), 200

@app.route('/api/TitleData', methods=['POST'])
def titled_data():
    return jsonify({"MOTD": "<color=#ff8d0a>   [ > WELCOME TO PROJECT LUNAR! < ]  </color>\n<color=#ff00ee>   BOOST https://discord.gg/gaj8PHafq3 FOR EVERY COSMETIC!</color>\n<color=#783be3>   CREDITS: Z4EU, LUNRRR</color>\n<color=#2ef1ff>   THIS GAME TAKES YOU INTO OLDER AND NEWER GTAG UPDATES!</color><color=#bb1b1b>\n   YOU DON'T NEED TO CHANGE YOU'RE NAME!!</color>"})

@app.route("/api/CheckForBadName", methods=["POST", "GET"])
def checkforbadname():
    rjson = request.get_json() 
    function_result = rjson["FunctionArgument"]
    playfab_id = rjson["CallerEntityProfile"]["Lineage"]["MasterPlayerAccountId"]
    name = function_result["name"].upper()
    forRoom = function_result["forRoom"]

    if forRoom:
        return jsonify({"result": 0})

    requests.post(
        url=f"https://{settings.TitleId}.playfabapi.com/Admin/UpdateUserTitleDisplayName",
        json={
            "DisplayName": name,
            "PlayFabId": playfab_id,
        },
        headers=settings.GetAuthHeaders(),
    )
    return jsonify({"result": 0})

@app.route("/api/GetAcceptedAgreements", methods=['POST', 'GET'])
def GetAcceptedAgreements():
    return jsonify({"PrivacyPolicy": "1.1.28", "TOS": "11.05.22.2"}), 200

@app.route("/api/SubmitAcceptedAgreements", methods=['POST', 'GET'])
def SubmitAcceptedAgreements():
    return jsonify({"PrivacyPolicy": "1.1.28", "TOS": "11.05.22.2"}), 200

@app.route('/api/GetName', methods=['POST', 'GET'])
def GetName():
    return jsonify({"result": f"GORILLA{random.randint(1000,9999)}"})

@app.route("/api/ConsumeOculusIAP", methods=["POST", "GET"])
def consumeoculusiap():
    rjson = request.get_json()
    userId = rjson.get("userID")
    nonce = rjson.get("nonce")
    sku = rjson.get("sku")

    req = requests.post(
        url=f"https://graph.oculus.com/consume_entitlement?nonce={nonce}&user_id={userId}&sku={sku}&access_token={settings.ApiKey}",
        headers={
            "content-type": "application/json"
        }
    )

    if bool(req.json().get("success")):
        return jsonify({"result": True})
    else:
        return jsonify({"error": True})

@app.route("/api/ReturnMyOculusHashV2", methods=["POST", "GET"])
def returnmyoculushashv2():
    return ReturnFunctionJson(request.get_json(), "ReturnMyOculusHash")

@app.route("/api/ReturnCurrentVersionV2", methods=["POST", "GET"])
def returncurrentversionv2():
    return ReturnFunctionJson(request.get_json(), "ReturnCurrentVersion")

@app.route("/api/TryDistributeCurrencyV2", methods=["POST"])
def TryDistributeCurrencyV2():
    if request.method != "POST":
        return "", 404
        
    rjson = request.json
    sr_a_day = 100
    current_player_id = rjson.get("CallerEntityProfile", {}).get("Lineage", {}).get("MasterPlayerAccountId")

    get_data_response = requests.post(
        f"https://{settings.TitleId}.playfabapi.com/Server/GetUserReadOnlyData",
        headers=settings.GetAuthHeaders(),
        json={
            "PlayFabId": current_player_id,
            "Keys": ["DailyLogin"]
        }
    )

    daily_login_value = get_data_response.json().get("data").get("Data").get("DailyLogin", {}).get("Value", None)

    last_login_date = None
    if daily_login_value:
        last_login_date = datetime.fromisoformat(daily_login_value.replace("Z", "+00:00")).astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    if not last_login_date or last_login_date < datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0):
        requests.post(
            f"https://{settings.TitleId}.playfabapi.com/Server/AddUserVirtualCurrency",
            headers=settings.GetAuthHeaders(),
            json={
                "PlayFabId": current_player_id,
                "VirtualCurrency": "SR",
                "Amount": sr_a_day
            }
        )

        requests.post(
            f"https://{settings.TitleId}.playfabapi.com/Server/UpdateUserReadOnlyData",
            headers=settings.GetAuthHeaders(),
            json={
                "PlayFabId": current_player_id,
                "Data": {
                    "DailyLogin": datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
                }
            }
        )

    return "", 200

@app.route("/api/BroadCastMyRoomV2", methods=["POST", "GET"])
def broadcastmyroomv2():
    return ReturnFunctionJson(request.get_json(), "BroadCastMyRoom", request.get_json().get("FunctionParameter", {}))

@app.route("/api/ShouldUserAutomutePlayer", methods=["POST", "GET"])
def shoulduserautomuteplayer():
    return jsonify(muteCache)

@app.route("/api/photon", methods=["POST", "GET"])
def photonauth():
    print(f"Received {request.method} request at /api/photon")
    
    if request.method.upper() == "GET":
        # Safe query string arguments or fallback extraction logic
        Ticket = request.args.get("Ticket")
        Platform = request.args.get("Platform")
        Nonce = request.args.get("Nonce")
        
        userId = Ticket.split('-')[0] if Ticket else None
        print(f"Extracted userId: {userId}")

        if userId is None or len(userId) != 16:
            return jsonify({'resultCode': 2, 'message': 'Invalid token', 'userId': None, 'nickname': None})

        if Platform != 'Quest':
            return jsonify({'Error': 'Bad request', 'Message': 'Invalid platform!'}), 403

        if Nonce is None:
            return jsonify({'Error': 'Bad request', 'Message': 'Not Authenticated!'}), 304

        req = requests.post(
            url=f"https://{settings.TitleId}.playfabapi.com/Server/GetUserAccountInfo",
            json={"PlayFabId": userId},
            headers=settings.GetAuthHeaders()
        )

        if req.status_code == 200:
            nickName = req.json().get("data", {}).get("UserInfo", {}).get("TitleInfo", {}).get("DisplayName")
            return jsonify({
                'resultCode': 1,
                'message': f'Authenticated user {userId.lower()} title {settings.TitleId.lower()}',
                'userId': f'{userId.upper()}',
                'nickname': nickName
            })
        else:
            return jsonify({'resultCode': 0, 'message': "Something went wrong", 'userId': None, 'nickname': None})

    elif request.method.upper() == "POST":
        rjson = request.get_json()
        ticket = rjson.get("Ticket")
        userId = ticket.split('-')[0] if ticket else None

        if userId is None or len(userId) != 16:
            return jsonify({'resultCode': 2, 'message': 'Invalid token', 'userId': None, 'nickname': None})

        req = requests.post(
             url=f"https://{settings.TitleId}.playfabapi.com/Server/GetUserAccountInfo",
             json={"PlayFabId": userId},
             headers=settings.GetAuthHeaders()
        )

        if req.status_code == 200:
             nickName = req.json().get("data", {}).get("UserInfo", {}).get("TitleInfo", {}).get("DisplayName")
             return jsonify({
                 'resultCode': 1,
                 'message': f'Authenticated user {userId.lower()} title {settings.TitleId.lower()}',
                 'userId': f'{userId.upper()}',
                 'nickname': nickName
             })
        else:
             return jsonify({'resultCode': 0, 'message': "Something went wrong", 'userId': None, 'nickname': None})

if __name__ == "__main__":
    app.run("0.0.0.0", 8080)
