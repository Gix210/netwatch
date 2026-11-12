"""E-mail notifications (Gmail SMTP with an app password):
one alert per device and category within the cooldown, plus an optional daily digest."""
import html
import smtplib
import threading
import time
from collections import defaultdict
from email.message import EmailMessage

from .util import fmt_ts, local_ip, now, ssl_context

ACTION_FR = {"alert": "journalisé (alerte)", "block": "bloqué", "log": "journalisé"}


class Notifier:
    def __init__(self, cfg, store):
        self.cfg = cfg
        self.store = store
        self.last = {}
        self.lock = threading.Lock()

    def settings(self):
        return self.cfg.get("alerts") or {}

    def enabled(self):
        a = self.settings()
        return bool(a.get("email_enabled") and a.get("to") and a.get("smtp_host") and a.get("smtp_user"))

    def dashboard_url(self, path=""):
        return f"http://{local_ip()}:{self.cfg.get('web', 'port')}/{path}"

    # ---- immediate alerts --------------------------------------------------
    def on_event(self, ev):
        """ev: ts, device_id, device, ip, domain, category, label, action."""
        if not self.enabled():
            return
        cooldown = int(self.settings().get("cooldown_min") or 30) * 60
        key = (ev["device_id"], ev["category"])
        t = now()
        with self.lock:
            if t - self.last.get(key, 0) < cooldown:
                return
            self.last[key] = t
        threading.Thread(target=self._send_alert, args=(ev,), name="nw-mail", daemon=True).start()

    def _send_alert(self, ev):
        site = self.cfg.get("site_name")
        subject = f"[NetWatch {site}] {ev['device']} → {ev['domain']} ({ev['label']})"
        text = (f"Appareil : {ev['device']} ({ev['ip']})\nDomaine : {ev['domain']}\nCatégorie : {ev['label']}\n"
                f"Action : {ACTION_FR.get(ev['action'], ev['action'])}\nHeure : {fmt_ts(ev['ts'])}\n\n"
                f"Tableau de bord : {self.dashboard_url('#/alertes')}\n")
        body = (f"<p><b>Appareil :</b> {html.escape(ev['device'])} ({html.escape(ev['ip'])})<br>"
                f"<b>Domaine :</b> {html.escape(ev['domain'])}<br><b>Catégorie :</b> {html.escape(ev['label'])}<br>"
                f"<b>Action :</b> {ACTION_FR.get(ev['action'], ev['action'])}<br><b>Heure :</b> {fmt_ts(ev['ts'])}</p>"
                f"<p><a href=\"{self.dashboard_url('#/alertes')}\">Ouvrir le tableau de bord</a></p>"
                f"<p style=\"color:#666;font-size:12px\">Les alertes de cet appareil pour cette catégorie sont regroupées "
                f"pendant {self.settings().get('cooldown_min', 30)} minutes.</p>")
        err = self.send(subject, text, body)
        if err:
            self.store.log("error", f"Courriel d'alerte non envoyé : {err}")

    # ---- transport --------------------------------------------------------------
    def send(self, subject, text, body_html=None, to=None):
        a = self.settings()
        recipients = [x.strip() for x in (to or a.get("to") or "").replace(";", ",").split(",") if x.strip()]
        if not recipients:
            return "aucun destinataire"
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = a.get("smtp_user")
        msg["To"] = ", ".join(recipients)
        msg.set_content(text)
        if body_html:
            msg.add_alternative(f"<html><body style=\"font-family:Segoe UI,Arial,sans-serif\">{body_html}</body></html>",
                                subtype="html")
        port = int(a.get("smtp_port") or 587)
        try:
            if port == 465:
                conn = smtplib.SMTP_SSL(a.get("smtp_host"), port, timeout=25, context=ssl_context())
            else:
                conn = smtplib.SMTP(a.get("smtp_host"), port, timeout=25)
            with conn as s:
                s.ehlo()
                if port != 465:
                    s.starttls(context=ssl_context())
                    s.ehlo()
                s.login(a.get("smtp_user"), a.get("smtp_password") or "")
                s.send_message(msg)
            return ""
        except Exception as e:
            return str(e)

    def test(self):
        site = self.cfg.get("site_name")
        return self.send(f"[NetWatch {site}] Courriel de test", "NetWatch peut envoyer des courriels. Tout est en ordre.",
                         "<p>NetWatch peut envoyer des courriels. Tout est en ordre.</p>")

    # ---- daily digest --------------------------------------------------------------
    def digest(self, day):
        rows = self.store.digest_data(day)
        site = self.cfg.get("site_name")
        subject = f"[NetWatch {site}] Rapport du {day}"
        if not rows:
            return self.send(subject, f"Aucune alerte ni blocage le {day}.", f"<p>Aucune alerte ni blocage le {day}.</p>")
        by_dev = defaultdict(list)
        for r in rows:
            by_dev[r["device"]].append(r)
        text_lines, html_parts = [f"Rapport NetWatch du {day}", ""], [f"<h3>Rapport NetWatch du {day}</h3>"]
        labels = {c["key"]: c["label"] for c in self.store.categories()}
        for dev, items in by_dev.items():
            total = sum(i["n"] for i in items)
            text_lines.append(f"{dev} ({items[0]['ip']}) : {total} événement(s)")
            html_parts.append(f"<p><b>{html.escape(dev)}</b> ({html.escape(items[0]['ip'] or '')}) : {total} événement(s)</p><ul>")
            for i in items[:15]:
                lab = labels.get(i["category"], i["category"])
                act = "bloqué" if i["action"] == "block" else "journalisé"
                text_lines.append(f"  - {i['domain']} [{lab}] x{i['n']} ({act})")
                html_parts.append(f"<li>{html.escape(i['domain'])} <i>[{html.escape(lab)}]</i> ×{i['n']} ({act})</li>")
            html_parts.append("</ul>")
        text_lines += ["", f"Tableau de bord : {self.dashboard_url()}"]
        html_parts.append(f"<p><a href=\"{self.dashboard_url()}\">Ouvrir le tableau de bord</a></p>")
        return self.send(subject, "\n".join(text_lines), "".join(html_parts))
