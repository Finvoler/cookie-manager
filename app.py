from __future__ import annotations

import base64
import json
import os
import secrets
import string
import sys
import uuid
from datetime import datetime
from pathlib import Path
from tkinter import Canvas, TclError, messagebox

import customtkinter as ctk
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

APP_NAME = "Cookie Manager"
VAULT_MARKER = "cookie-manager-vault-v1"

COLORS = {
    "ink": "#1b2430",
    "muted": "#687385",
    "card": "#fbfdff",
    "line": "#dce7f3",
    "line_focus": "#8bb6f5",
    "primary": "#2f6df6",
    "primary_hover": "#245ad2",
    "primary_soft": "#e9f1ff",
    "danger": "#e5484d",
    "danger_soft": "#fff0f0",
}


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


VAULT_FILE = app_dir() / "vault.dat"


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, path: Path, password: str, salt: bytes, payload: dict):
        self.path = path
        self.salt = salt
        self.payload = payload
        self._fernet = Fernet(self._derive_key(password, salt))

    @property
    def entries(self) -> list[dict]:
        return self.payload.setdefault("entries", [])

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    @classmethod
    def create(cls, path: Path, password: str) -> "Vault":
        salt = os.urandom(16)
        payload = {"marker": VAULT_MARKER, "entries": []}
        vault = cls(path, password, salt, payload)
        vault.save()
        return vault

    @classmethod
    def open(cls, path: Path, password: str) -> "Vault":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            salt = base64.b64decode(raw["salt"])
            token = raw["token"].encode("utf-8")
            fernet = Fernet(cls._derive_key(password, salt))
            payload = json.loads(fernet.decrypt(token).decode("utf-8"))
        except (OSError, KeyError, json.JSONDecodeError, InvalidToken, ValueError) as exc:
            raise VaultError("主密码不正确，或保险库文件已损坏。") from exc

        if payload.get("marker") != VAULT_MARKER:
            raise VaultError("保险库格式不兼容。")
        return cls(path, password, salt, payload)

    def save(self) -> None:
        token = self._fernet.encrypt(json.dumps(self.payload, ensure_ascii=False).encode("utf-8"))
        data = {
            "version": 1,
            "salt": base64.b64encode(self.salt).decode("utf-8"),
            "token": token.decode("utf-8"),
        }
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def preview(text: str, limit: int = 52) -> str:
    clean = " ".join(text.split())
    return clean if len(clean) <= limit else clean[: limit - 1] + "..."


def make_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*_-+=?"
    return "".join(secrets.choice(alphabet) for _ in range(length))


class GradientCanvas(Canvas):
    def __init__(self, master, colors: tuple[str, str, str]):
        super().__init__(master, highlightthickness=0, bd=0)
        self.colors = colors
        self.bind("<Configure>", lambda _event: self.draw_gradient())

    @staticmethod
    def _hex_to_rgb(value: str) -> tuple[int, int, int]:
        value = value.lstrip("#")
        return tuple(int(value[index : index + 2], 16) for index in (0, 2, 4))

    @staticmethod
    def _rgb_to_hex(rgb: tuple[int, int, int]) -> str:
        return "#%02x%02x%02x" % rgb

    def draw_gradient(self) -> None:
        self.delete("gradient")
        width = max(self.winfo_width(), 1)
        height = max(self.winfo_height(), 1)
        top = self._hex_to_rgb(self.colors[0])
        middle = self._hex_to_rgb(self.colors[1])
        bottom = self._hex_to_rgb(self.colors[2])

        for row in range(height):
            if row < height / 2:
                ratio = row / max(height / 2, 1)
                start, end = top, middle
            else:
                ratio = (row - height / 2) / max(height / 2, 1)
                start, end = middle, bottom
            rgb = tuple(int(start[i] + (end[i] - start[i]) * ratio) for i in range(3))
            self.create_line(0, row, width, row, fill=self._rgb_to_hex(rgb), tags="gradient")
        self.lower("gradient")


def setup_window(window: ctk.CTk | ctk.CTkToplevel) -> None:
    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("blue")
    window.configure(fg_color="#eef5ff")


def bind_select_all(widget: ctk.CTkTextbox) -> None:
    def select_all(_event=None):
        try:
            widget._textbox.tag_add("sel", "1.0", "end-1c")
            widget._textbox.mark_set("insert", "1.0")
            widget._textbox.see("insert")
        except TclError:
            pass
        return "break"

    widget.bind("<Control-a>", select_all)
    widget.bind("<Control-A>", select_all)


def set_textbox_text(widget: ctk.CTkTextbox, text: str, disabled: bool = False) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", text)
    if disabled:
        widget.configure(state="disabled")


class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        setup_window(self)
        self.vault: Vault | None = None
        self.password_var = ctk.StringVar()
        self.confirm_var = ctk.StringVar()
        self.show_password_var = ctk.BooleanVar(value=False)
        self.is_new = not VAULT_FILE.exists()

        self.title(APP_NAME)
        self.geometry("540x460")
        self.resizable(False, False)
        self._build()

    def _build(self) -> None:
        bg = GradientCanvas(self, ("#e9f6ff", "#f7efff", "#fff8ed"))
        bg.place(relx=0, rely=0, relwidth=1, relheight=1)

        card = ctk.CTkFrame(self, width=430, height=340, corner_radius=30, fg_color="#fbfdff", border_width=1, border_color="#dce7f3")
        card.place(relx=0.5, rely=0.5, anchor="center")
        card.grid_propagate(False)
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card, text="Cookie Manager", font=("Microsoft YaHei UI", 24, "bold"), text_color=COLORS["ink"]).grid(row=0, column=0, sticky="w", padx=30, pady=(28, 4))
        subtitle = "创建主密码，开始使用本地加密保险库" if self.is_new else "输入主密码，解锁你的本地保险库"
        ctk.CTkLabel(card, text=subtitle, font=("Microsoft YaHei UI", 13), text_color=COLORS["muted"]).grid(row=1, column=0, sticky="w", padx=30, pady=(0, 24))

        self.password_entry = ctk.CTkEntry(card, textvariable=self.password_var, show="*", height=46, corner_radius=16, border_width=1, border_color=COLORS["line"], placeholder_text="主密码", font=("Microsoft YaHei UI", 13))
        self.password_entry.grid(row=2, column=0, sticky="ew", padx=30, pady=(0, 14))
        self.password_entry.focus_set()

        if self.is_new:
            self.confirm_entry = ctk.CTkEntry(card, textvariable=self.confirm_var, show="*", height=46, corner_radius=16, border_width=1, border_color=COLORS["line"], placeholder_text="再次输入主密码", font=("Microsoft YaHei UI", 13))
            self.confirm_entry.grid(row=3, column=0, sticky="ew", padx=30, pady=(0, 12))
            button_row = 5
            button_text = "创建并进入"
        else:
            button_row = 4
            button_text = "解锁保险库"

        ctk.CTkSwitch(card, text="显示主密码", variable=self.show_password_var, command=self._toggle_password, progress_color=COLORS["primary"], font=("Microsoft YaHei UI", 12)).grid(row=button_row - 1, column=0, sticky="w", padx=30, pady=(0, 16))
        ctk.CTkButton(card, text=button_text, height=48, corner_radius=18, fg_color=COLORS["primary"], hover_color=COLORS["primary_hover"], font=("Microsoft YaHei UI", 14, "bold"), command=self._submit).grid(row=button_row, column=0, sticky="ew", padx=30, pady=(0, 18))
        ctk.CTkLabel(card, text="数据只保存在本机，主密码不会被保存", font=("Microsoft YaHei UI", 12), text_color=COLORS["muted"]).grid(row=button_row + 1, column=0, sticky="w", padx=30)
        self.bind("<Return>", lambda _event: self._submit())

    def _toggle_password(self) -> None:
        show = "" if self.show_password_var.get() else "*"
        self.password_entry.configure(show=show)
        if self.is_new:
            self.confirm_entry.configure(show=show)

    def _submit(self) -> None:
        password = self.password_var.get()
        if len(password) < 6:
            messagebox.showwarning("密码太短", "主密码至少需要 6 位。")
            return

        try:
            if self.is_new:
                if password != self.confirm_var.get():
                    messagebox.showwarning("确认失败", "两次输入的主密码不一致。")
                    return
                self.vault = Vault.create(VAULT_FILE, password)
            else:
                self.vault = Vault.open(VAULT_FILE, password)
        except VaultError as exc:
            messagebox.showerror("无法解锁", str(exc))
            return
        self.destroy()


class MainWindow(ctk.CTk):
    def __init__(self, vault: Vault):
        super().__init__()
        setup_window(self)
        self.vault = vault
        self.selected_entry: dict | None = None
        self.name_var = ctk.StringVar()
        self.username_var = ctk.StringVar()
        self.password_var = ctk.StringVar()
        self.search_var = ctk.StringVar()
        self.status_var = ctk.StringVar(value=f"已载入 {len(self.vault.entries)} 条记录")
        self.show_form_password = ctk.BooleanVar(value=False)
        self.show_detail_password = ctk.BooleanVar(value=False)
        self.result_buttons: dict[str, ctk.CTkButton] = {}

        self.title(APP_NAME)
        self.geometry("1180x760")
        self.minsize(1040, 660)
        self._build()
        self.refresh_results()

    def _build(self) -> None:
        bg = GradientCanvas(self, ("#e8f6ff", "#f5efff", "#fff9ee"))
        bg.place(relx=0, rely=0, relwidth=1, relheight=1)

        shell = ctk.CTkFrame(self, fg_color="transparent")
        shell.pack(fill="both", expand=True, padx=28, pady=24)
        shell.grid_columnconfigure(0, weight=1)
        shell.grid_rowconfigure(2, weight=1)

        self._build_header(shell)
        self._build_nav(shell)

        self.body = ctk.CTkFrame(shell, fg_color="transparent")
        self.body.grid(row=2, column=0, sticky="nsew")
        self.body.grid_columnconfigure(0, weight=1)
        self.body.grid_rowconfigure(0, weight=1)

        self.add_page = ctk.CTkFrame(self.body, fg_color="transparent")
        self.search_page = ctk.CTkFrame(self.body, fg_color="transparent")
        for page in (self.add_page, self.search_page):
            page.grid(row=0, column=0, sticky="nsew")

        self._build_add_page()
        self._build_search_page()
        self._switch_page("保存资料")

    def _build_header(self, shell: ctk.CTkFrame) -> None:
        header = ctk.CTkFrame(shell, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 18))
        header.grid_columnconfigure(0, weight=1)

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(title_box, text="Cookie 与账号密码管理器", font=("Microsoft YaHei UI", 25, "bold"), text_color=COLORS["ink"]).pack(anchor="w")
        ctk.CTkLabel(title_box, text="离线加密保存账号、密码、备注、网站 Cookie、Token 或其它密钥文本。", font=("Microsoft YaHei UI", 13), text_color=COLORS["muted"]).pack(anchor="w", pady=(3, 0))

        status = ctk.CTkFrame(header, corner_radius=18, fg_color="#ffffff", border_width=1, border_color=COLORS["line"])
        status.grid(row=0, column=1, sticky="e")
        ctk.CTkLabel(status, textvariable=self.status_var, font=("Microsoft YaHei UI", 12), text_color=COLORS["muted"]).pack(padx=16, pady=10)

    def _build_nav(self, shell: ctk.CTkFrame) -> None:
        nav = ctk.CTkFrame(shell, height=58, corner_radius=24, fg_color="#fbfdff", border_width=1, border_color="#dce7f3")
        nav.grid(row=1, column=0, sticky="ew", pady=(0, 18))
        nav.grid_propagate(False)
        nav.grid_columnconfigure(0, weight=1)

        self.segment = ctk.CTkSegmentedButton(nav, values=["保存资料", "搜索查看"], selected_color=COLORS["primary"], selected_hover_color=COLORS["primary_hover"], unselected_color="#edf4fb", unselected_hover_color="#e2ecf6", corner_radius=18, height=38, font=("Microsoft YaHei UI", 13, "bold"), command=self._switch_page)
        self.segment.grid(row=0, column=0, sticky="w", padx=10, pady=10)
        self.segment.set("保存资料")

        ctk.CTkLabel(nav, text="文字区域支持鼠标选择、Ctrl+A、Ctrl+C", font=("Microsoft YaHei UI", 12), text_color=COLORS["muted"]).grid(row=0, column=1, sticky="e", padx=18)

    def _card(self, parent, title: str, subtitle: str | None = None) -> ctk.CTkFrame:
        card = ctk.CTkFrame(parent, corner_radius=26, fg_color=COLORS["card"], border_width=1, border_color=COLORS["line"])
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(card, text=title, font=("Microsoft YaHei UI", 17, "bold"), text_color=COLORS["ink"]).grid(row=0, column=0, sticky="w", padx=22, pady=(20, 2))
        if subtitle:
            ctk.CTkLabel(card, text=subtitle, font=("Microsoft YaHei UI", 12), text_color=COLORS["muted"], wraplength=360, justify="left").grid(row=1, column=0, sticky="w", padx=22, pady=(0, 14))
        return card

    def _entry(self, parent, variable: ctk.StringVar, placeholder: str, show: str | None = None) -> ctk.CTkEntry:
        return ctk.CTkEntry(parent, textvariable=variable, placeholder_text=placeholder, show=show, height=44, corner_radius=15, border_width=1, border_color=COLORS["line"], fg_color="#ffffff", font=("Microsoft YaHei UI", 13))

    def _textbox(self, parent, height: int, font_family: str = "Microsoft YaHei UI") -> ctk.CTkTextbox:
        textbox = ctk.CTkTextbox(parent, height=height, corner_radius=18, border_width=1, border_color=COLORS["line"], fg_color="#ffffff", text_color=COLORS["ink"], font=(font_family, 13), wrap="word")
        bind_select_all(textbox)
        return textbox

    def _build_add_page(self) -> None:
        self.add_page.grid_columnconfigure(0, weight=3)
        self.add_page.grid_columnconfigure(1, weight=2)
        self.add_page.grid_rowconfigure(0, weight=1)

        info_card = self._card(self.add_page, "保存一条资料", "名称用于搜索；备注也会参与关键词匹配。")
        info_card.grid(row=0, column=0, sticky="nsew", padx=(0, 16))
        info_card.grid_rowconfigure(10, weight=1)

        ctk.CTkLabel(info_card, text="名称", font=("Microsoft YaHei UI", 12, "bold"), text_color=COLORS["ink"]).grid(row=2, column=0, sticky="w", padx=22, pady=(4, 6))
        self.name_entry = self._entry(info_card, self.name_var, "例如：Canvas 课程站、GitHub 小号、某网站会话")
        self.name_entry.grid(row=3, column=0, sticky="ew", padx=22, pady=(0, 14))

        ctk.CTkLabel(info_card, text="账号", font=("Microsoft YaHei UI", 12, "bold"), text_color=COLORS["ink"]).grid(row=4, column=0, sticky="w", padx=22, pady=(0, 6))
        self.username_entry = self._entry(info_card, self.username_var, "邮箱、用户名或手机号，可留空")
        self.username_entry.grid(row=5, column=0, sticky="ew", padx=22, pady=(0, 14))

        password_label = ctk.CTkFrame(info_card, fg_color="transparent")
        password_label.grid(row=6, column=0, sticky="ew", padx=22, pady=(0, 6))
        ctk.CTkLabel(password_label, text="密码", font=("Microsoft YaHei UI", 12, "bold"), text_color=COLORS["ink"]).pack(side="left")
        ctk.CTkSwitch(password_label, text="显示", variable=self.show_form_password, command=self._toggle_form_password, progress_color=COLORS["primary"], font=("Microsoft YaHei UI", 12)).pack(side="right")

        self.password_entry = self._entry(info_card, self.password_var, "保存密码，或点击生成强密码", show="*")
        self.password_entry.grid(row=7, column=0, sticky="ew", padx=22, pady=(0, 14))

        tools = ctk.CTkFrame(info_card, fg_color="transparent")
        tools.grid(row=8, column=0, sticky="ew", padx=22, pady=(0, 14))
        ctk.CTkButton(tools, text="生成强密码", width=138, height=40, corner_radius=14, fg_color=COLORS["primary_soft"], hover_color="#d9e8ff", text_color=COLORS["primary"], font=("Microsoft YaHei UI", 13, "bold"), command=self._fill_password).pack(side="left")
        ctk.CTkButton(tools, text="清空表单", width=118, height=40, corner_radius=14, fg_color="#f3f6fa", hover_color="#e8eef5", text_color=COLORS["ink"], font=("Microsoft YaHei UI", 13), command=self.clear_form).pack(side="left", padx=(10, 0))

        ctk.CTkLabel(info_card, text="备注", font=("Microsoft YaHei UI", 12, "bold"), text_color=COLORS["ink"]).grid(row=9, column=0, sticky="w", padx=22, pady=(0, 6))
        self.note_text = self._textbox(info_card, height=150)
        self.note_text.grid(row=10, column=0, sticky="nsew", padx=22, pady=(0, 22))

        secret_card = self._card(self.add_page, "网站 Cookie / Token / 密钥文本", "可选。适合保存浏览器 Cookie、API Token、会话令牌或需要原样保留的长文本。")
        secret_card.grid(row=0, column=1, sticky="nsew")
        secret_card.grid_rowconfigure(2, weight=1)
        self.cookie_text = self._textbox(secret_card, height=360, font_family="Consolas")
        self.cookie_text.grid(row=2, column=0, sticky="nsew", padx=22, pady=(0, 16))
        ctk.CTkButton(secret_card, text="加密保存这条记录", height=48, corner_radius=18, fg_color=COLORS["primary"], hover_color=COLORS["primary_hover"], font=("Microsoft YaHei UI", 14, "bold"), command=self.save_entry).grid(row=3, column=0, sticky="ew", padx=22, pady=(0, 22))

    def _build_search_page(self) -> None:
        self.search_page.grid_columnconfigure(0, weight=2)
        self.search_page.grid_columnconfigure(1, weight=3)
        self.search_page.grid_rowconfigure(0, weight=1)

        list_card = self._card(self.search_page, "搜索资料", "关键词会匹配名称和备注。")
        list_card.grid(row=0, column=0, sticky="nsew", padx=(0, 16))
        list_card.grid_rowconfigure(3, weight=1)

        search_box = ctk.CTkFrame(list_card, fg_color="transparent")
        search_box.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 14))
        search_box.grid_columnconfigure(0, weight=1)
        self.search_entry = self._entry(search_box, self.search_var, "输入名称或备注关键词")
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.search_entry.bind("<KeyRelease>", lambda _event: self.refresh_results())
        ctk.CTkButton(search_box, text="搜索", width=82, height=42, corner_radius=15, fg_color=COLORS["primary"], hover_color=COLORS["primary_hover"], font=("Microsoft YaHei UI", 13, "bold"), command=self.refresh_results).grid(row=0, column=1)

        self.results_frame = ctk.CTkScrollableFrame(list_card, corner_radius=18, fg_color="#f4f8fc", scrollbar_button_color="#c7d8ea", scrollbar_button_hover_color="#a8bfd9")
        self.results_frame.grid(row=3, column=0, sticky="nsew", padx=22, pady=(0, 22))
        self.results_frame.grid_columnconfigure(0, weight=1)

        detail_card = self._card(self.search_page, "查看完整信息", "详情文本支持直接拖选、Ctrl+A、Ctrl+C，也可以使用一键复制。")
        detail_card.grid(row=0, column=1, sticky="nsew")
        detail_card.grid_rowconfigure(7, weight=1)

        self.detail_title = ctk.CTkLabel(detail_card, text="还没有选择记录", font=("Microsoft YaHei UI", 20, "bold"), text_color=COLORS["ink"], anchor="w")
        self.detail_title.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 14))

        fields = ctk.CTkFrame(detail_card, fg_color="transparent")
        fields.grid(row=3, column=0, sticky="ew", padx=22, pady=(0, 12))
        fields.grid_columnconfigure(0, weight=1)
        fields.grid_columnconfigure(1, weight=1)
        self.detail_username = self._readonly_field(fields, "账号")
        self.detail_username.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        password_box = ctk.CTkFrame(fields, fg_color="transparent")
        password_box.grid(row=0, column=1, sticky="ew", padx=(10, 0))
        password_box.grid_columnconfigure(0, weight=1)
        self.detail_password = self._readonly_field(password_box, "密码")
        self.detail_password.grid(row=0, column=0, sticky="ew")
        ctk.CTkSwitch(password_box, text="显示", variable=self.show_detail_password, command=self.show_selected, progress_color=COLORS["primary"], font=("Microsoft YaHei UI", 12)).grid(row=0, column=1, padx=(10, 0), pady=(22, 0))

        copy_row = ctk.CTkFrame(detail_card, fg_color="transparent")
        copy_row.grid(row=4, column=0, sticky="ew", padx=22, pady=(0, 14))
        self._copy_button(copy_row, "复制账号", lambda: self.copy_field("username")).pack(side="left")
        self._copy_button(copy_row, "复制密码", lambda: self.copy_field("password")).pack(side="left", padx=(8, 0))
        self._copy_button(copy_row, "复制 Cookie/Token", lambda: self.copy_field("cookie")).pack(side="left", padx=(8, 0))
        ctk.CTkButton(copy_row, text="删除记录", width=110, height=38, corner_radius=14, fg_color=COLORS["danger_soft"], hover_color="#ffe0e0", text_color=COLORS["danger"], font=("Microsoft YaHei UI", 13, "bold"), command=self.delete_selected).pack(side="right")

        ctk.CTkLabel(detail_card, text="备注、网站 Cookie、Token 或密钥文本", font=("Microsoft YaHei UI", 12, "bold"), text_color=COLORS["ink"]).grid(row=6, column=0, sticky="w", padx=22, pady=(0, 6))
        self.detail_text = self._textbox(detail_card, height=260, font_family="Consolas")
        self.detail_text.grid(row=7, column=0, sticky="nsew", padx=22, pady=(0, 22))
        set_textbox_text(self.detail_text, "从左侧选择一条记录后，这里会显示完整内容。", disabled=True)

    def _readonly_field(self, parent, label: str) -> ctk.CTkFrame:
        box = ctk.CTkFrame(parent, fg_color="transparent")
        box.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(box, text=label, font=("Microsoft YaHei UI", 12, "bold"), text_color=COLORS["ink"]).grid(row=0, column=0, sticky="w", pady=(0, 5))
        entry = ctk.CTkEntry(box, height=42, corner_radius=14, border_width=1, border_color=COLORS["line"], fg_color="#ffffff", font=("Microsoft YaHei UI", 13))
        entry.grid(row=1, column=0, sticky="ew")
        box.entry = entry
        return box

    def _copy_button(self, parent, text: str, command) -> ctk.CTkButton:
        return ctk.CTkButton(parent, text=text, width=108, height=38, corner_radius=14, fg_color="#eef5ff", hover_color="#dbeaff", text_color=COLORS["primary"], font=("Microsoft YaHei UI", 13, "bold"), command=command)

    def _switch_page(self, page_name: str) -> None:
        if page_name == "保存资料":
            self.add_page.tkraise()
            self.name_entry.focus_set()
        else:
            self.search_page.tkraise()
            self.search_entry.focus_set()
            self.refresh_results()

    def _toggle_form_password(self) -> None:
        self.password_entry.configure(show="" if self.show_form_password.get() else "*")

    def _fill_password(self) -> None:
        self.password_var.set(make_password())
        self.show_form_password.set(True)
        self._toggle_form_password()
        self.status_var.set("已生成强密码，可选择后复制或直接保存")

    def clear_form(self) -> None:
        self.name_var.set("")
        self.username_var.set("")
        self.password_var.set("")
        set_textbox_text(self.note_text, "")
        set_textbox_text(self.cookie_text, "")
        self.status_var.set("表单已清空")

    def save_entry(self) -> None:
        name = self.name_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        note = self.note_text.get("1.0", "end").strip()
        cookie = self.cookie_text.get("1.0", "end").strip()

        if not name:
            messagebox.showwarning("缺少名称", "请至少填写名称，这样后续才能搜索。")
            self.name_entry.focus_set()
            return
        if not username and not password and not cookie:
            messagebox.showwarning("内容为空", "请至少填写账号、密码或 Cookie/Token/密钥文本之一。")
            return

        timestamp = now_text()
        self.vault.entries.append({"id": str(uuid.uuid4()), "name": name, "username": username, "password": password, "note": note, "cookie": cookie, "created_at": timestamp, "updated_at": timestamp})
        self.vault.save()
        self.clear_form()
        self.refresh_results()
        self.status_var.set(f"已加密保存：{name}")
        messagebox.showinfo("保存成功", "记录已加密保存。可以到“搜索查看”页面查看、选择和复制。")

    def refresh_results(self) -> None:
        keyword = self.search_var.get().strip().casefold()
        for child in self.results_frame.winfo_children():
            child.destroy()
        self.result_buttons.clear()

        matches = []
        for entry in sorted(self.vault.entries, key=lambda item: item.get("updated_at", ""), reverse=True):
            name = entry.get("name", "")
            note = entry.get("note", "")
            if not keyword or keyword in name.casefold() or keyword in note.casefold():
                matches.append(entry)

        if not matches:
            empty = ctk.CTkFrame(self.results_frame, corner_radius=18, fg_color="#ffffff", border_width=1, border_color=COLORS["line"])
            empty.grid(row=0, column=0, sticky="ew", padx=6, pady=6)
            ctk.CTkLabel(empty, text="没有匹配记录", font=("Microsoft YaHei UI", 14, "bold"), text_color=COLORS["ink"]).pack(anchor="w", padx=16, pady=(16, 2))
            ctk.CTkLabel(empty, text="换一个关键词，或先保存一条资料。", font=("Microsoft YaHei UI", 12), text_color=COLORS["muted"]).pack(anchor="w", padx=16, pady=(0, 16))
        else:
            for row, entry in enumerate(matches):
                self._result_card(row, entry)

        self.status_var.set(f"找到 {len(matches)} 条记录，共 {len(self.vault.entries)} 条")
        if matches and (not self.selected_entry or self.selected_entry.get("id") not in {entry.get("id") for entry in matches}):
            self.selected_entry = matches[0]
            self.show_selected()
            self._highlight_result(matches[0].get("id", ""))

    def _result_card(self, row: int, entry: dict) -> None:
        name = entry.get("name", "未命名")
        username = entry.get("username", "未填写账号") or "未填写账号"
        note = preview(entry.get("note", "无备注") or "无备注")
        updated = entry.get("updated_at", "")
        text = f"{name}\n{username}  ·  {updated}\n{note}"
        button = ctk.CTkButton(self.results_frame, text=text, anchor="w", height=84, corner_radius=18, fg_color="#ffffff", hover_color="#eaf3ff", text_color=COLORS["ink"], border_width=1, border_color=COLORS["line"], font=("Microsoft YaHei UI", 12), command=lambda selected=entry: self._select_entry(selected))
        button.grid(row=row, column=0, sticky="ew", padx=6, pady=6)
        self.result_buttons[entry.get("id", "")] = button

    def _select_entry(self, entry: dict) -> None:
        self.selected_entry = entry
        self.show_selected()
        self._highlight_result(entry.get("id", ""))

    def _highlight_result(self, entry_id: str) -> None:
        for current_id, button in self.result_buttons.items():
            if current_id == entry_id:
                button.configure(fg_color="#e8f1ff", border_color=COLORS["line_focus"])
            else:
                button.configure(fg_color="#ffffff", border_color=COLORS["line"])

    def show_selected(self) -> None:
        if not self.selected_entry:
            return
        entry = self.selected_entry
        self.detail_title.configure(text=entry.get("name", "未命名"))
        self._set_entry_value(self.detail_username.entry, entry.get("username", ""))
        password = entry.get("password", "")
        self._set_entry_value(self.detail_password.entry, password if self.show_detail_password.get() else "•" * len(password))

        sections = []
        note = entry.get("note", "")
        cookie = entry.get("cookie", "")
        if note:
            sections.append("备注\n" + note)
        if cookie:
            sections.append("网站 Cookie / Token / 密钥文本\n" + cookie)
        sections.append(f"创建时间：{entry.get('created_at', '')}\n更新时间：{entry.get('updated_at', '')}")
        set_textbox_text(self.detail_text, "\n\n".join(sections), disabled=True)

    @staticmethod
    def _set_entry_value(entry: ctk.CTkEntry, value: str) -> None:
        entry.configure(state="normal")
        entry.delete(0, "end")
        entry.insert(0, value)
        entry.configure(state="readonly")

    def copy_field(self, field: str) -> None:
        if not self.selected_entry:
            messagebox.showwarning("未选择", "请先在左侧选择一条记录。")
            return
        value = self.selected_entry.get(field, "")
        if not value:
            messagebox.showinfo("无内容", "这个字段目前是空的。")
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status_var.set("已复制到剪贴板")

    def delete_selected(self) -> None:
        if not self.selected_entry:
            messagebox.showwarning("未选择", "请先在左侧选择一条记录。")
            return
        name = self.selected_entry.get("name", "未命名")
        if not messagebox.askyesno("确认删除", f"确定删除“{name}”吗？"):
            return
        selected_id = self.selected_entry.get("id")
        self.vault.payload["entries"] = [entry for entry in self.vault.entries if entry.get("id") != selected_id]
        self.vault.save()
        self.selected_entry = None
        self.detail_title.configure(text="还没有选择记录")
        self._set_entry_value(self.detail_username.entry, "")
        self._set_entry_value(self.detail_password.entry, "")
        set_textbox_text(self.detail_text, "从左侧选择一条记录后，这里会显示完整内容。", disabled=True)
        self.refresh_results()
        self.status_var.set(f"已删除：{name}")


def main() -> None:
    login = LoginWindow()
    login.mainloop()
    if login.vault is None:
        return
    app = MainWindow(login.vault)
    app.mainloop()


if __name__ == "__main__":
    main()