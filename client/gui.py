import os
import sys
import time
import queue
import argparse
import threading
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog

sys.path.insert(0, os.path.dirname(__file__)) #client/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from client.client import VaultClient, Connection, ClientError, KEY_CHANGED
from secure_share import Rejected

# graphical client -- same VaultClient underneath, only the look is new
# security in the ui:
#   safety number: big 4-digit groups + must type the other side's last group
#   failures: can't be clicked away for 3 s, and never offer "open anyway"
#   share: only verified contacts can be picked

INK, MUTED, WHITE = "#2E2A33", "#7A737E", "#FFFFFF"
PINK, PINK_D = "#F7C6D9", "#C2477A"
GREEN, GREEN_D = "#CDEFD7", "#3C8A5A"
SOFT = "#FAF7F9"
FONT = "Segoe UI"


def style_app(root):
    root.configure(bg=WHITE)
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=WHITE, foreground=INK, font=(FONT, 10))
    s.configure("TFrame", background=WHITE)
    s.configure("Soft.TFrame", background=SOFT)
    s.configure("TLabel", background=WHITE, foreground=INK)
    s.configure("Soft.TLabel", background=SOFT)
    s.configure("Title.TLabel", font=(FONT, 20, "bold"))
    s.configure("Muted.TLabel", foreground=MUTED)
    s.configure("TButton", background=GREEN, foreground=INK, borderwidth=0, padding=(10, 5))
    s.map("TButton", background=[("active", "#B8E6C6"), ("disabled", "#EEEEEE")])
    s.configure("Pink.TButton", background=PINK)
    s.map("Pink.TButton", background=[("active", "#F2B0CB")])
    s.configure("TEntry", fieldbackground=SOFT, borderwidth=0, padding=6)
    s.configure("Treeview", background=WHITE, fieldbackground=WHITE, rowheight=28, borderwidth=0)
    s.configure("Treeview.Heading", background=SOFT, foreground=MUTED, borderwidth=0, font=(FONT, 9, "bold"))
    s.map("Treeview", background=[("selected", PINK)], foreground=[("selected", INK)])


class App:
    def __init__(self, root, host, port, data_dir):
        self.root = root
        self.host, self.port, self.data_dir = host, port, data_dir
        self.client = None
        self.results = queue.Queue()
        root.title("SecureVault")
        root.geometry("1120x640")
        root.minsize(1040, 560)
        style_app(root)
        self.body = ttk.Frame(root)
        self.body.pack(fill="both", expand=True)
        self.show_login()
        self.poll()

    # helpers

    def clear(self):
        for w in self.body.winfo_children():
            w.destroy()

    def busy(self, work, done, fail=None):
        #network + Argon2id take time, so run them off the ui thread
        #(tk isn't thread-safe: the worker only puts the result in a queue)
        self.root.config(cursor="watch")
        def run():
            try:
                self.results.put((done, work()))
            except Exception as e:
                self.results.put((fail or self.on_error, e))
        threading.Thread(target=run, daemon=True).start()

    def poll(self):
        while not self.results.empty():
            callback, value = self.results.get()
            self.root.config(cursor="")
            callback(value)
        self.root.after(50, self.poll)

    def on_error(self, e):
        if isinstance(e, Rejected):
            self.failure(str(e))
        elif isinstance(e, ClientError) and str(e) == KEY_CHANGED:
            self.failure("key changed", key_changed=True)
        else:
            self.toast(str(e) or "something went wrong", PINK)

    def toast(self, text, color=GREEN):
        bar = tk.Label(self.root, text=text, bg=color, fg=INK, font=(FONT, 10), padx=14, pady=8)
        bar.place(relx=0.5, rely=0.96, anchor="s")
        self.root.after(3500, bar.destroy)

    def connect(self):
        if self.client is None:
            self.client = VaultClient(Connection(self.host, self.port).send, self.data_dir)
        return self.client

    # login / sign-up

    def show_login(self):
        self.clear()
        box = ttk.Frame(self.body, style="Soft.TFrame", padding=36)
        box.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(box, text="SecureVault", style="Title.TLabel", background=SOFT).pack(anchor="w")
        ttk.Label(box, text=f"server {self.host}:{self.port}", style="Muted.TLabel", background=SOFT).pack(anchor="w", pady=(0, 18))

        user, pw = tk.StringVar(), tk.StringVar()
        for label, var, show in [("username", user, ""), ("password", pw, "•")]:
            ttk.Label(box, text=label, style="Soft.TLabel").pack(anchor="w")
            e = ttk.Entry(box, textvariable=var, show=show, width=32)
            e.pack(fill="x", pady=(2, 12))
        msg = ttk.Label(box, text="", foreground=PINK_D, background=SOFT)
        msg.pack(anchor="w")

        def go(action):
            name, password = user.get().strip(), pw.get()
            if not name or not password:
                msg.config(text="enter a username and a password")
                return
            msg.config(text="working..." if action == "login" else "creating your keys...")
            def work():
                c = self.connect()
                (c.login if action == "login" else c.signup)(name, password)
            self.busy(work, lambda _: self.show_main(),
                      lambda e: msg.config(text=str(e) if not isinstance(e, OSError) else "can't reach the server"))

        row = ttk.Frame(box, style="Soft.TFrame")
        row.pack(fill="x", pady=(8, 0))
        ttk.Button(row, text="Log in", command=lambda: go("login")).pack(side="left")
        ttk.Button(row, text="Sign up", style="Pink.TButton", command=lambda: go("signup")).pack(side="left", padx=8)
        self.root.bind("<Return>", lambda _: go("login"))

    # main screen

    def show_main(self):
        self.root.unbind("<Return>")
        self.clear()
        top = ttk.Frame(self.body, padding=(20, 16, 20, 8))
        top.pack(fill="x")
        ttk.Label(top, text="SecureVault", style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Log out", style="Pink.TButton", command=self.logout).pack(side="right")
        ttk.Button(top, text="Password", command=self.change_password).pack(side="right", padx=8)
        ttk.Label(top, text=f"  {self.client.username}", style="Muted.TLabel").pack(side="left", pady=(8, 0))

        main = ttk.Frame(self.body, padding=(20, 0, 20, 20))
        main.pack(fill="both", expand=True)

        #contacts
        side = ttk.Frame(main, style="Soft.TFrame", padding=14, width=250)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        ttk.Label(side, text="Contacts", font=(FONT, 12, "bold"), background=SOFT).pack(anchor="w")
        self.contacts = tk.Listbox(side, bg=SOFT, fg=INK, bd=0, highlightthickness=0, font=(FONT, 10),
                                   selectbackground=PINK, selectforeground=INK, activestyle="none")
        self.contacts.pack(fill="both", expand=True, pady=8)
        self.contacts.bind("<Double-Button-1>", lambda _: self.open_contact())
        add = tk.StringVar()
        ttk.Entry(side, textvariable=add).pack(fill="x")
        ttk.Button(side, text="Add / check contact",
                   command=lambda: self.add_contact(add.get().strip())).pack(fill="x", pady=(6, 0))

        #documents
        docs = ttk.Frame(main, padding=(16, 0, 0, 0))
        docs.pack(side="left", fill="both", expand=True)
        bar = ttk.Frame(docs)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Label(bar, text="Documents", font=(FONT, 12, "bold")).pack(side="left")
        for text, cmd, st in [("Refresh", self.refresh, "TButton"), ("Prove", self.prove, "TButton"),
                              ("Download", self.download, "TButton"), ("Share", self.share, "Pink.TButton"),
                              ("New version", self.new_version, "TButton"), ("Upload", self.upload, "Pink.TButton")]:
            ttk.Button(bar, text=text, style=st, command=cmd).pack(side="right", padx=(6, 0))

        cols = ("name", "version", "owner", "size", "date")
        self.table = ttk.Treeview(docs, columns=cols, show="headings", selectmode="browse")
        for c, w in zip(cols, (260, 70, 110, 90, 150)):
            self.table.heading(c, text=c.upper(), anchor="w")
            self.table.column(c, width=w, anchor="w")
        self.table.pack(fill="both", expand=True)
        self.refresh()

    def refresh(self):
        def work():
            return self.client.list(), self.client.pinned()
        def done(result):
            items, pinned = result
            self.table.delete(*self.table.get_children())
            for d in items:
                size = f"{d['size']:,} B"
                date = time.strftime("%Y-%m-%d %H:%M", time.localtime(d["timestamp"]))
                self.table.insert("", "end", iid=d["doc_id"],
                                  values=(d["filename"], f"v{d['version']}", d["owner"], size, date))
            self.contacts.delete(0, "end")
            for name, entry in sorted(pinned.items()):
                self.contacts.insert("end", f"{'✓' if entry['verified'] else '•'}  {name}")
                self.contacts.itemconfig("end", fg=GREEN_D if entry["verified"] else PINK_D)
        self.busy(work, done)

    def selected_doc(self):
        sel = self.table.selection()
        if not sel:
            self.toast("select a document first", PINK)
            return None
        return sel[0]

    # actions

    def upload(self):
        path = filedialog.askopenfilename(title="Upload a file")
        if path:
            self.busy(lambda: self.client.upload(path), lambda _: (self.toast("uploaded and encrypted"), self.refresh()))

    def new_version(self):
        doc = self.selected_doc()
        if doc is None:
            return
        path = filedialog.askopenfilename(title="Choose the new version")
        if path:
            self.busy(lambda: self.client.update(doc, path), lambda _: (self.toast("new version uploaded"), self.refresh()))

    def share(self):
        doc = self.selected_doc()
        if doc is None:
            return
        verified = [n for n, e in self.client.pinned().items() if e["verified"]]
        if not verified:
            #the ui refuses: no verified contact, no sharing
            self.toast("verify a contact first (compare the safety number)", PINK)
            return
        win = self.dialog("Share with")
        ttk.Label(win, text="Only verified contacts can receive files.", style="Muted.TLabel").pack(anchor="w")
        who = tk.StringVar(value=verified[0])
        for n in sorted(verified):
            ttk.Radiobutton(win, text=f"✓  {n}", variable=who, value=n).pack(anchor="w", pady=2)
        def go():
            win.destroy()
            self.busy(lambda: self.client.share(doc, who.get()), lambda _: self.toast(f"shared with {who.get()}"))
        ttk.Button(win, text="Share", style="Pink.TButton", command=go).pack(anchor="e", pady=(12, 0))

    def download(self):
        doc = self.selected_doc()
        if doc is None:
            return
        folder = filedialog.askdirectory(title="Save to")
        if folder:
            self.busy(lambda: self.client.download(doc, folder), self.downloaded)

    def downloaded(self, result):
        path, sender, verified = result
        win = self.dialog("Download")
        tk.Label(win, text="✓", font=(FONT, 34, "bold"), fg=GREEN_D, bg=WHITE).pack()
        ttk.Label(win, text="The file is intact", font=(FONT, 13, "bold")).pack()
        ttk.Label(win, text=f"signed by {sender}").pack(pady=(2, 0))
        if not verified:
            tk.Label(win, text=f"{sender} is NOT verified yet: compare the safety number",
                     fg=PINK_D, bg=WHITE, font=(FONT, 10, "bold")).pack(pady=6)
        ttk.Label(win, text=f"saved as {os.path.basename(str(path))}", style="Muted.TLabel").pack(pady=(6, 10))
        ttk.Button(win, text="Close", command=win.destroy).pack()

    def prove(self):
        doc = self.selected_doc()
        if doc is None:
            return
        folder = filedialog.askdirectory(title="Save the proof to")
        if folder:
            self.busy(lambda: self.client.prove(doc, folder),
                      lambda p: self.toast(f"proof saved: {os.path.basename(str(p))}"))

    def change_password(self):
        old = simpledialog.askstring("Password", "Current password", show="•", parent=self.root)
        new = old and simpledialog.askstring("Password", "New password", show="•", parent=self.root)
        if old and new:
            self.busy(lambda: self.client.passwd(old, new), lambda _: self.toast("password changed"))

    def logout(self):
        self.client.logout()
        self.show_login()

    # contacts + safety number

    def add_contact(self, name):
        if not name:
            return
        self.busy(lambda: self.client.contact(name), lambda number: (self.refresh(), self.safety(name, number)))

    def open_contact(self):
        sel = self.contacts.curselection()
        if sel:
            self.add_contact(self.contacts.get(sel[0])[3:])

    def safety(self, name, number):
        groups = number.split()
        win = self.dialog(f"Safety number with {name}")
        ttk.Label(win, text=f"Read this to {name} by phone or in person.\nIt must match their screen exactly.",
                  justify="left").pack(anchor="w")
        grid = ttk.Frame(win)
        grid.pack(pady=14)
        for i, g in enumerate(groups):
            tk.Label(grid, text=g, font=("Consolas", 22, "bold"), fg=INK,
                     bg=GREEN if i % 2 == 0 else PINK, padx=12, pady=8).grid(row=0, column=i, padx=4)

        if self.client.pinned().get(name, {}).get("verified"):
            ttk.Label(win, text=f"✓ {name} is already verified", foreground=GREEN_D).pack()
            ttk.Button(win, text="Close", command=win.destroy).pack(pady=(10, 0))
            return

        #no one-click "match": the user types the last group they HEARD from the other side
        ttk.Label(win, text=f"Type the LAST 4 digits {name} reads to you:").pack(anchor="w")
        typed = tk.StringVar()
        ttk.Entry(win, textvariable=typed, width=10, font=("Consolas", 16)).pack(anchor="w", pady=6)
        msg = ttk.Label(win, text="", foreground=PINK_D)
        msg.pack(anchor="w")

        def confirm():
            if typed.get().strip() != groups[-1]:
                msg.config(text="doesn't match: do NOT share. Someone may be in the middle.")
                return
            self.client.verify(name)
            win.destroy()
            self.toast(f"{name} verified")
            self.refresh()
        row = ttk.Frame(win)
        row.pack(fill="x", pady=(8, 0))
        ttk.Button(row, text="Verify", command=confirm).pack(side="right")
        ttk.Button(row, text="Not now", style="Pink.TButton", command=win.destroy).pack(side="right", padx=8)

    # failures: loud, plain, and hard to click away

    def failure(self, reason, key_changed=False):
        win = self.dialog("Rejected" if not key_changed else "Blocked", modal=True)
        win.protocol("WM_DELETE_WINDOW", lambda: None)   #no closing with the X
        tk.Label(win, text="✕", font=(FONT, 34, "bold"), fg=PINK_D, bg=WHITE).pack()
        if key_changed:
            title, text = "Blocked: key changed", ("This contact's key is not the one you saved.\n"
                                                   "Someone may be pretending to be them.\n"
                                                   "Nothing was shared or opened.")
        else:
            title, text = f"Rejected: {reason}", ("This file did NOT pass the checks.\n"
                                                  "It was not opened and not saved.")
        tk.Label(win, text=title, font=(FONT, 13, "bold"), fg=PINK_D, bg=WHITE).pack()
        ttk.Label(win, text=text, justify="center").pack(pady=10)
        btn = ttk.Button(win, text="I understand (3)", state="disabled", command=win.destroy)
        btn.pack()
        def tick(n):
            if n == 0:
                btn.config(text="I understand", state="normal")
            elif btn.winfo_exists():
                btn.config(text=f"I understand ({n})")
                win.after(1000, tick, n - 1)
        win.after(1000, tick, 2)

    def dialog(self, title, modal=False):
        win = tk.Toplevel(self.root, bg=WHITE, padx=28, pady=22)
        win.title(title)
        win.resizable(False, False)
        win.transient(self.root)
        if modal:
            win.grab_set()
        return win


def main():
    parser = argparse.ArgumentParser(description="SecureVault graphical client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--data", default="client_data")
    args = parser.parse_args()

    root = tk.Tk()
    App(root, args.host, args.port, args.data)
    root.mainloop()


if __name__ == "__main__":
    main()
