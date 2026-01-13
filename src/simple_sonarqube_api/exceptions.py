# src/simple_sonarqube_api/exceptions.py

class SonarQubeError(Exception):
    """
    Excepción base de la librería.

    Todas las excepciones específicas de simple-sonarqube-api heredan de esta.
    Permite al consumidor capturar de forma genérica cualquier error del cliente:

        try:
            ...
        except SonarQubeError as e:
            ...
    """
    pass


class SonarQubeAuthError(SonarQubeError):
    """
    Error de autenticación (401).

    Suele indicar:
    - Token inválido o caducado.
    - URL base incorrecta.
    """
    pass


class SonarQubePermissionError(SonarQubeError):
    """
    Error de permisos (403).

    Muy habitual al intentar acceder a:
    - Código fuente (/api/sources/*)
    - Snippets de issues

    Normalmente requiere:
    - Permiso "Browse" en el proyecto
    - Permiso "See Source Code"
    - Token de usuario (squ_...) en lugar de token técnico.
    """
    pass


class SonarQubeNotFoundError(SonarQubeError):
    """
    Recurso no encontrado (404).

    Puede deberse a:
    - Issue key inexistente.
    - Project/component key errónea.
    - Endpoint no disponible en la versión de SonarQube.
    """
    pass


class SonarQubeRateLimitError(SonarQubeError):
    """
    Límite de peticiones alcanzado (429).

    Suele indicar:
    - Demasiadas peticiones en poco tiempo.
    - Necesidad de aumentar backoff o delay entre llamadas.
    """
    pass


class SonarQubeProtocolError(SonarQubeError):
    """
    Error de protocolo o formato inesperado.

    Se lanza cuando la respuesta del servidor no tiene la estructura
    esperada por el cliente (cambios de API, bugs, proxies intermedios, etc.).
    """
    pass
