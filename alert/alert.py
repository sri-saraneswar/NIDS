"""
=========================================================
Network Intrusion Detection System (NIDS)

Module : Alert Manager

Manages GUI popup alerts using tkinter.

Features:
    One popup per attack
    Auto-close on attack finish
    Thread-safe via queue
    Color-coded severity
    Non-blocking background thread

=========================================================
"""


import threading
import queue


try:
    import tkinter as tk
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False





# =====================================================
# Severity Colors
# =====================================================


SEVERITY_COLORS = {

    "CRITICAL": "#dc2626",

    "HIGH": "#ea580c",

    "MEDIUM": "#d97706",

    "LOW": "#ca8a04"

}


SEVERITY_BG = {

    "CRITICAL": "#1a0000",

    "HIGH": "#1a0800",

    "MEDIUM": "#1a1000",

    "LOW": "#1a1800"

}





# =====================================================
# Alert Manager
# =====================================================


class AlertManager:
    """
    Manages GUI popup alerts for detected attacks.

    Uses a dedicated tkinter thread to display
    non-blocking popup windows. Each attack gets
    exactly one popup. Popups auto-close when
    the attack session finishes.
    """


    def __init__(self):
        """Initialize the alert manager."""

        self._active_popups = {}

        self._action_queue = queue.Queue()

        self._root = None

        self._thread = None

        self._running = False





    # =============================================
    # Start Alert Thread
    # =============================================


    def start(self):
        """
        Start the tkinter event loop on
        a background daemon thread.
        """

        if not TKINTER_AVAILABLE:
            return


        self._running = True


        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="AlertThread"
        )

        self._thread.start()





    # =============================================
    # Stop Alert Thread
    # =============================================


    def stop(self):
        """Stop the alert thread and close all popups."""

        self._running = False


        if self._root:

            try:
                self._root.quit()
            except Exception:
                pass





    # =============================================
    # Show Alert (Thread-Safe)
    # =============================================


    def show_alert(self, attack):
        """
        Queue a new alert popup for an attack.

        Only creates one popup per attack_key.
        Duplicate calls are ignored.

        Args:
            attack: Attack dictionary with attack_key,
                    attack_type, severity, source_ip,
                    destination_ip, details.
        """

        if not TKINTER_AVAILABLE:
            return

        if not self._running:
            return


        attack_key = attack.get("attack_key")


        # Prevent duplicate popups

        if attack_key in self._active_popups:
            return


        self._action_queue.put(
            ("show", attack)
        )





    # =============================================
    # Close Alert (Thread-Safe)
    # =============================================


    def close_alert(self, attack):
        """
        Queue the closure of an attack popup.

        Args:
            attack: Attack dictionary containing
                    the attack_key to close.
        """

        if not TKINTER_AVAILABLE:
            return

        if not self._running:
            return


        attack_key = attack.get("attack_key")


        self._action_queue.put(
            ("close", attack_key)
        )





    # =============================================
    # Background Event Loop
    # =============================================


    def _run_loop(self):
        """
        Main tkinter event loop running
        on the background thread.

        Periodically polls the action queue
        for new show/close commands.
        """

        try:

            self._root = tk.Tk()

            self._root.withdraw()

            self._root.title("NIDS Alerts")


            self._process_queue()


            self._root.mainloop()


        except Exception:

            self._running = False





    # =============================================
    # Process Action Queue
    # =============================================


    def _process_queue(self):
        """
        Process pending actions from the queue.

        Called every 200ms from the tkinter
        event loop via root.after().
        """

        if not self._running:
            return


        try:

            while not self._action_queue.empty():

                action, data = self._action_queue.get_nowait()


                if action == "show":

                    self._create_popup(data)


                elif action == "close":

                    self._destroy_popup(data)


        except queue.Empty:
            pass

        except Exception:
            pass


        # Schedule next check

        if self._running and self._root:

            self._root.after(
                200,
                self._process_queue
            )





    # =============================================
    # Create Popup Window
    # =============================================


    def _create_popup(self, attack):
        """
        Create a tkinter Toplevel popup for an attack.

        Args:
            attack: Attack dictionary with all fields.
        """

        attack_key = attack.get("attack_key")


        # Already showing this attack

        if attack_key in self._active_popups:
            return


        severity = attack.get(
            "severity", "LOW"
        )

        fg_color = SEVERITY_COLORS.get(
            severity, "#ca8a04"
        )

        bg_color = SEVERITY_BG.get(
            severity, "#1a1800"
        )



        # ── Create Window ──────────────────────

        popup = tk.Toplevel(self._root)

        popup.title(
            f"⚠ NIDS Alert - "
            f"{attack.get('attack_type', 'Unknown')}"
        )

        popup.configure(bg=bg_color)

        popup.attributes("-topmost", True)

        popup.resizable(False, False)


        # Center on screen

        width = 420
        height = 300

        screen_w = popup.winfo_screenwidth()
        screen_h = popup.winfo_screenheight()

        x = (screen_w - width) // 2
        y = (screen_h - height) // 2

        popup.geometry(
            f"{width}x{height}+{x}+{y}"
        )



        # ── Header ─────────────────────────────

        header = tk.Label(
            popup,
            text="⚠ NETWORK INTRUSION DETECTED",
            font=("Consolas", 14, "bold"),
            fg=fg_color,
            bg=bg_color,
            pady=10
        )

        header.pack(
            fill=tk.X
        )


        # ── Separator ──────────────────────────

        sep = tk.Frame(
            popup,
            height=2,
            bg=fg_color
        )

        sep.pack(
            fill=tk.X,
            padx=20
        )


        # ── Content Frame ──────────────────────

        content = tk.Frame(
            popup,
            bg=bg_color
        )

        content.pack(
            fill=tk.BOTH,
            expand=True,
            padx=20,
            pady=10
        )


        # Attack details

        details = [
            ("Attack Type",
             attack.get("attack_type", "Unknown")),

            ("Severity",
             severity),

            ("Source",
             attack.get("source_ip", "Unknown")),

            ("Destination",
             attack.get("destination_ip", "Unknown")),

            ("Status",
             attack.get("status", "ACTIVE")),

            ("Packets",
             str(attack.get("packet_count", 1)))
        ]


        for label_text, value_text in details:

            row = tk.Frame(
                content,
                bg=bg_color
            )

            row.pack(
                fill=tk.X,
                pady=2
            )


            label = tk.Label(
                row,
                text=f"{label_text:16}: ",
                font=("Consolas", 10),
                fg="#888888",
                bg=bg_color,
                anchor="w"
            )

            label.pack(
                side=tk.LEFT
            )


            # Color severity value

            value_color = (
                fg_color
                if label_text == "Severity"
                else "#ffffff"
            )


            value = tk.Label(
                row,
                text=value_text,
                font=("Consolas", 10, "bold"),
                fg=value_color,
                bg=bg_color,
                anchor="w"
            )

            value.pack(
                side=tk.LEFT
            )


        # ── Footer ─────────────────────────────

        footer = tk.Label(
            popup,
            text="This alert will close automatically"
                 " when the attack ends.",
            font=("Consolas", 8),
            fg="#666666",
            bg=bg_color,
            pady=8
        )

        footer.pack(
            side=tk.BOTTOM
        )


        # Store reference

        self._active_popups[attack_key] = popup


        # Handle manual close

        popup.protocol(
            "WM_DELETE_WINDOW",
            lambda: self._on_manual_close(
                attack_key
            )
        )





    # =============================================
    # Destroy Popup Window
    # =============================================


    def _destroy_popup(self, attack_key):
        """
        Close and destroy a popup by attack key.

        Args:
            attack_key: The tuple key identifying
                        the attack popup.
        """

        if attack_key in self._active_popups:

            popup = self._active_popups.pop(
                attack_key
            )

            try:
                popup.destroy()
            except Exception:
                pass





    # =============================================
    # Manual Close Handler
    # =============================================


    def _on_manual_close(self, attack_key):
        """
        Handle user manually closing a popup.

        Args:
            attack_key: The tuple key of the popup.
        """

        self._destroy_popup(attack_key)
