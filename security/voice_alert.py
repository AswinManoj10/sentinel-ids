"""Voice alert — non-blocking TTS warning."""

import threading


class VoiceAlert:

    def warn_async(self):
        threading.Thread(target=self._speak, daemon=True).start()

    def _speak(self):
        try:
            import pyttsx3
            engine = pyttsx3.init()
            engine.setProperty("rate", 160)
            engine.setProperty("volume", 0.9)
            engine.say("Warning. Unauthorized access detected. Security team has been notified.")
            engine.runAndWait()
        except Exception:
            pass   # silent fallback — voice is non-critical
