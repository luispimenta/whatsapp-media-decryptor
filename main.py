from flask import Flask, request, jsonify
import requests
import base64
import json
from base64 import urlsafe_b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

app = Flask(__name__)

def _b64_urlsafe_decode(s: str) -> bytes:
    """Corrige padding para base64 url-safe"""
    s = s.replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    return base64.b64decode(s)

def _convert_media_key_format(media_key_input) -> bytes:
    """
    Converte mediaKey de qualquer formato para bytes
    
    Suporta:
    - String base64 (novo formato)
    - String base64 url-safe (novo formato)
    - JSON com índices numéricos (formato antigo do Evolution)
    - Objeto Python com índices numéricos (formato antigo)
    """
    
    # Se for string, tenta JSON primeiro (formato antigo)
    if isinstance(media_key_input, str):
        # Tenta parsear como JSON (formato antigo: {"0": 152, "1": 88, ...})
        try:
            obj = json.loads(media_key_input)
            if isinstance(obj, dict):
                # Converte {0: 152, 1: 88, ...} para bytes
                return bytes([obj[str(i)] for i in range(len(obj))])
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Se não for JSON, trata como base64
        # Tenta base64 url-safe primeiro
        try:
            return _b64_urlsafe_decode(media_key_input)
        except Exception:
            # Tenta base64 padrão
            try:
                return base64.b64decode(media_key_input)
            except Exception as e:
                raise ValueError(f"Não foi possível decodificar mediaKey: {str(e)}")
    
    # Se for dict/list (formato antigo como objeto Python)
    elif isinstance(media_key_input, dict):
        return bytes([media_key_input[str(i)] for i in range(len(media_key_input))])
    
    # Se for bytes já, retorna direto
    elif isinstance(media_key_input, bytes):
        return media_key_input
    
    raise ValueError(f"Formato de mediaKey não suportado: {type(media_key_input)}")

@app.route("/decode-media", methods=["POST"])
def decode_media():
    payload = request.get_json(force=True)

    media_url = payload.get("media_url")
    media_key_input = payload.get("media_key")  # Pode ser string, JSON ou dict
    mimetype = payload.get("mimetype")
    auth_token = payload.get("auth_token")

    if not media_url or not media_key_input or not mimetype:
        return jsonify({
            "error": "Parâmetros 'media_url', 'media_key' e 'mimetype' são obrigatórios"
        }), 400

    try:
        # ========== 1. CONVERTER MEDIA_KEY ==========
        try:
            media_key = _convert_media_key_format(media_key_input)
        except Exception as e:
            return jsonify({
                "error": "Erro ao converter mediaKey",
                "details": str(e)
            }), 400

        if len(media_key) != 32:
            return jsonify({
                "error": "media_key decodificado não tem 32 bytes",
                "media_key_len": len(media_key),
                "info": "Provável formato incorreto"
            }), 400

        # ========== 2. BAIXAR ARQUIVO ENCRIPTADO ==========
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        resp = requests.get(media_url, headers=headers, timeout=20)
        if resp.status_code != 200:
            return jsonify({
                "error": "Falha ao baixar mídia",
                "http_status": resp.status_code,
                "content_type": resp.headers.get("content-type")
            }), 400

        enc_data = resp.content
        if not enc_data or len(enc_data) <= 10:
            return jsonify({
                "error": "Arquivo de mídia inválido ou muito curto"
            }), 400

        # ========== 3. DEFINIR INFO HKDF BASEADO NO TIPO ==========
        if mimetype.startswith("image/"):
            info = b"WhatsApp Image Keys"
        elif mimetype.startswith("audio/"):
            info = b"WhatsApp Audio Keys"
        elif mimetype.startswith("video/"):
            info = b"WhatsApp Video Keys"
        elif mimetype.startswith("application/") or mimetype.startswith("text/") or mimetype.startswith("model/"):
            info = b"WhatsApp Document Keys"
        else:
            return jsonify({
                "error": f"Tipo de mídia não suportado: {mimetype}"
            }), 400

        # ========== 4. EXPANDIR CHAVE COM HKDF ==========
        expanded_key = HKDF(
            master=media_key,
            key_len=112,
            salt=None,
            hashmod=SHA256,
            num_keys=1,
            context=info
        )
        
        iv = expanded_key[0:16]
        enc_key = expanded_key[16:48]
        mac_key = expanded_key[48:80]

        # ========== 5. DESCRIPTOGRAFAR ==========
        ciphertext = enc_data[:-10]  # Remove 10 bytes de MAC

        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)

        # Remove padding PKCS7
        try:
            unpadded = unpad(decrypted, AES.block_size)
        except ValueError as e:
            return jsonify({
                "error": "Padding inválido na descriptografia",
                "details": str(e)
            }), 400

        # ========== 6. CONVERTER PARA BASE64 ==========
        base64_media = base64.b64encode(unpadded).decode("utf-8")

        return jsonify({
            "success": True,
            "base64": base64_media,
            "size": len(unpadded),
            "media_key_format_detected": "old_or_new"
        })

    except Exception as e:
        return jsonify({
            "error": "Erro interno",
            "details": str(e)
        }), 500

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
