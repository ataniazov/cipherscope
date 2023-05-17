#!/usr/bin/env python3

import customtkinter
import sys
import os
import subprocess
from PIL import Image


class CipherScope(customtkinter.CTk):
    APP_NAME = "CipherScope"
    WIDTH = 1280
    HEIGHT = 720

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # configure window
        self.title(self.APP_NAME)

        # self.geometry("700x450")
        # self.geometry(f"{1100}x{580}")
        # self.geometry(f"{1280}×{720}")
        # self.geometry(f"{1366}×{768}")

        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.minsize(self.WIDTH, self.HEIGHT)
        # self.resizable(False, False)

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.bind("<Control-q>", self.on_close)
        self.bind("<Control-w>", self.on_close)
        # self.createcommand("tk::mac::Quit", self.on_close)

        # set grid layout 1x2
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        current_path = os.path.dirname(os.path.realpath(__file__))

        # load images with light and dark mode image
        if sys.platform.startswith("win"):
            self.iconbitmap(os.path.join(
                current_path, "assets", "icons", "CipherScope.ico"))
        # image_path = os.path.join(os.path.dirname(
        #     os.path.realpath(__file__)), "images")
        image_path = os.path.join(current_path, "assets", "images")
        # self.logo_image = customtkinter.CTkImage(Image.open(os.path.join(
        #     image_path, "cipherscope_dark.png")), size=(26, 26))
        self.logo_image = customtkinter.CTkImage(light_image=Image.open(os.path.join(image_path, "cipherscope_dark.png")),
                                                 dark_image=Image.open(os.path.join(image_path, "cipherscope_light.png")), size=(26, 26))
        # self.large_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "large_image.png")), size=(500, 150))
        # self.image_icon_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "image_icon_light.png")), size=(20, 20))
        self.info_image = customtkinter.CTkImage(light_image=Image.open(os.path.join(image_path, "info_dark.png")),
                                                 dark_image=Image.open(os.path.join(image_path, "info_light.png")), size=(20, 20))
        self.block_image = customtkinter.CTkImage(light_image=Image.open(os.path.join(image_path, "block_dark.png")),
                                                  dark_image=Image.open(os.path.join(image_path, "block_light.png")), size=(20, 20))
        # self.block_lock_image = customtkinter.CTkImage(light_image=Image.open(os.path.join(image_path, "block_lock_dark.png")),
        #                                          dark_image=Image.open(os.path.join(image_path, "block_lock_light.png")), size=(20, 20))

        # create navigation frame
        self.navigation_frame = customtkinter.CTkFrame(self, corner_radius=0)
        self.navigation_frame.grid(row=0, column=0, sticky="nsew")
        self.navigation_frame.grid_rowconfigure(1, weight=1)

        self.navigation_frame_label = customtkinter.CTkLabel(
            self.navigation_frame, text="  " + self.APP_NAME, image=self.logo_image, compound="left", font=customtkinter.CTkFont(size=18, weight="bold"))
        self.navigation_frame_label.grid(row=0, column=0, padx=0, pady=20)

        # create scrollable frame
        # self.scrollable_frame = customtkinter.CTkScrollableFrame(self.navigation_frame, label_text="CTkScrollableFrame")
        self.scrollable_frame = customtkinter.CTkScrollableFrame(
            self.navigation_frame)
        self.scrollable_frame.grid(row=1, column=0, padx=(
            0, 0), pady=(0, 0), sticky="nsew")
        self.scrollable_frame.grid_columnconfigure(0, weight=1)

        self.appearance_mode_label = customtkinter.CTkLabel(
            self.navigation_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(
            row=2, column=0, padx=0, pady=(5, 0), sticky="s")
        self.appearance_mode_optionmenu = customtkinter.CTkOptionMenu(self.navigation_frame, values=[
                                                                      "System", "Light", "Dark"], command=self.change_appearance_mode_optionmenu_event)
        self.appearance_mode_optionmenu.grid(
            row=3, column=0, padx=0, pady=(0, 5), sticky="s")

        self.scaling_label = customtkinter.CTkLabel(
            self.navigation_frame, text="UI Scaling:", anchor="w")
        self.scaling_label.grid(row=4, column=0, padx=0,
                                pady=(5, 0), sticky="s")
        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self.navigation_frame, values=[
                                                               "80%", "90%", "100%", "110%", "120%", "200%"], command=self.change_scaling_event)
        self.scaling_optionemenu.grid(
            row=5, column=0, padx=0, pady=(0, 20), sticky="s")

        # create buttons in scrollable frame
        self.info_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text=self.APP_NAME,
                                                   fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                   image=self.info_image, anchor="w", command=self.info_button_event)
        self.info_button.grid(row=1, column=0, sticky="ew")

        self.aes_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="AES",
                                                  fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                  image=self.block_image, anchor="w", command=self.cipher_button_event)
        self.aes_button.grid(row=2, column=0, sticky="ew")

        self.chaskey_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Chaskey",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.block_image, anchor="w", command=self.block_button_event)
        self.chaskey_button.grid(row=3, column=0, sticky="ew")

        self.clefia_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="CLEFIA",
                                                     fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                     image=self.block_image, anchor="w", command=self.block_button_event)
        self.clefia_button.grid(row=4, column=0, sticky="ew")

        self.desxl_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="DESXL",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.desxl_button.grid(row=5, column=0, sticky="ew")

        self.fantomas_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Fantomas",
                                                       fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                       image=self.block_image, anchor="w", command=self.block_button_event)
        self.fantomas_button.grid(row=6, column=0, sticky="ew")

        self.gost_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="GOST",
                                                   fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                   image=self.block_image, anchor="w", command=self.block_button_event)
        self.gost_button.grid(row=7, column=0, sticky="ew")

        self.hight_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="HIGHT",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.hight_button.grid(row=8, column=0, sticky="ew")

        self.itubee_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="ITUbee",
                                                     fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                     image=self.block_image, anchor="w", command=self.block_button_event)
        self.itubee_button.grid(row=9, column=0, sticky="ew")

        self.kasumi_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="KASUMI",
                                                     fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                     image=self.block_image, anchor="w", command=self.block_button_event)
        self.kasumi_button.grid(row=10, column=0, sticky="ew")

        self.klein_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="KLEIN",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.klein_button.grid(row=11, column=0, sticky="ew")

        self.katan_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="KATAN",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.katan_button.grid(row=12, column=0, sticky="ew")

        self.ktantan_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="KTANTAN",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.block_image, anchor="w", command=self.block_button_event)
        self.ktantan_button.grid(row=13, column=0, sticky="ew")

        self.lblock_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="LBlock",
                                                     fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                     image=self.block_image, anchor="w", command=self.block_button_event)
        self.lblock_button.grid(row=14, column=0, sticky="ew")

        self.lea_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="LEA",
                                                  fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                  image=self.block_image, anchor="w", command=self.block_button_event)
        self.lea_button.grid(row=15, column=0, sticky="ew")

        self.led_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="LED",
                                                  fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                  image=self.block_image, anchor="w", command=self.block_button_event)
        self.led_button.grid(row=16, column=0, sticky="ew")

        self.mantis_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="MANTIS",
                                                     fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                     image=self.block_image, anchor="w", command=self.block_button_event)
        self.mantis_button.grid(row=17, column=0, sticky="ew")

        self.mcrypton_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="mCrypton",
                                                       fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                       image=self.block_image, anchor="w", command=self.block_button_event)
        self.mcrypton_button.grid(row=18, column=0, sticky="ew")

        self.midori_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Midori",
                                                     fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                     image=self.block_image, anchor="w", command=self.block_button_event)
        self.midori_button.grid(row=19, column=0, sticky="ew")

        self.misty1_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="MISTY1",
                                                     fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                     image=self.block_image, anchor="w", command=self.block_button_event)
        self.misty1_button.grid(row=20, column=0, sticky="ew")

        # create info frame
        # self.info_frame = customtkinter.CTkFrame(
        #     self, corner_radius=0, fg_color="transparent")
        self.info_frame = customtkinter.CTkFrame(self, corner_radius=0)
        self.info_frame.grid_columnconfigure(0, weight=1)

        # self.info_frame_large_image_label = customtkinter.CTkLabel(
        #     self.info_frame, text="", image=self.large_image)
        # self.info_frame_large_image_label.grid(
        #     row=0, column=0, padx=20, pady=10)

        # self.info_frame_button_1 = customtkinter.CTkButton(
        #     self.info_frame, text="", image=self.image_icon_image)
        # self.info_frame_button_1.grid(row=1, column=0, padx=20, pady=10)
        # self.info_frame_button_2 = customtkinter.CTkButton(
        #     self.info_frame, text="CTkButton", image=self.image_icon_image, compound="right")
        # self.info_frame_button_2.grid(row=2, column=0, padx=20, pady=10)
        # self.info_frame_button_3 = customtkinter.CTkButton(
        #     self.info_frame, text="CTkButton", image=self.image_icon_image, compound="top")
        # self.info_frame_button_3.grid(row=3, column=0, padx=20, pady=10)
        # self.info_frame_button_4 = customtkinter.CTkButton(
        #     self.info_frame, text="CTkButton", image=self.image_icon_image, compound="bottom", anchor="w")
        # self.info_frame_button_4.grid(row=4, column=0, padx=20, pady=10)

        # create cipher frame
        self.cipher_frame = customtkinter.CTkFrame(self, corner_radius=0)
        self.cipher_frame.grid_rowconfigure(2, weight=1)
        self.cipher_frame.grid_columnconfigure((1, 2), weight=1)

        # create main entry and button
        self.cipher_input_entrymode_button = customtkinter.CTkSegmentedButton(self.cipher_frame, values=[
                                                                              "Hex", "Text", "Bin"], command=self.change_cipher_input_entrymode_button_event)
        self.cipher_input_entrymode_button.grid(
            row=0, column=0, padx=(20, 0), pady=(20, 10), sticky="nsew")

        self.cipher_input_entry = customtkinter.CTkEntry(
            self.cipher_frame, placeholder_text="Plaintext")
        self.cipher_input_entry.grid(row=0, column=1, columnspan=2, padx=(
            20, 0), pady=(20, 10), sticky="nsew")

        self.cipher_transform_optionmenu = customtkinter.CTkOptionMenu(self.cipher_frame, dynamic_resizing=False, values=[
                                                                       "Encrypt", "Decrypt"], command=self.change_cipher_transform_optionmenu_event)
        self.cipher_transform_optionmenu.grid(
            row=0, column=3, padx=(20, 20), pady=(20, 10))

        self.cipher_mode_optionmenu = customtkinter.CTkOptionMenu(self.cipher_frame, dynamic_resizing=False, values=[
                                                                  "Block", "ECB", "CTR"], command=self.change_cipher_mode_optionmenu_event)
        self.cipher_mode_optionmenu.grid(
            row=1, column=0, padx=(20, 0), pady=(10, 20))

        self.cipher_key_entry = customtkinter.CTkEntry(
            self.cipher_frame, placeholder_text="Key")
        self.cipher_key_entry.grid(row=1, column=1, columnspan=2, padx=(
            20, 0), pady=(10, 20), sticky="nsew")

        self.cipher_iv_entry = customtkinter.CTkEntry(
            self.cipher_frame, placeholder_text="Initialization Vector")
        # self.cipher_iv_entry.grid(row=1, column=2, padx=(20, 0), pady=(10, 20), sticky="nsew")

        self.cipher_start_button = customtkinter.CTkButton(self.cipher_frame, text="Start", fg_color="transparent", border_width=2, hover_color=(
            "#3B8ED0", "#1F6AA5"), text_color=("gray10", "#DCE4EE"), command=self.change_cipher_start_button_event)
        # self.cipher_start_button = customtkinter.CTkButton(
        #     self.cipher_frame, text="Start")
        self.cipher_start_button.grid(row=1, column=3, padx=(
            20, 20), pady=(10, 20), sticky="nsew")

        self.cipher_output_entrymode_button = customtkinter.CTkSegmentedButton(self.cipher_frame, values=[
                                                                               "Hex", "Text", "Bin"], command=self.change_cipher_output_entrymode_button_event)
        self.cipher_output_entrymode_button.grid(
            row=3, column=0, padx=(20, 0), pady=(20, 20), sticky="nsew")

        self.cipher_output_entry = customtkinter.CTkEntry(
            self.cipher_frame, placeholder_text="Ciphertext")
        self.cipher_output_entry.grid(row=3, column=1, columnspan=3, padx=(
            20, 20), pady=(20, 20), sticky="nsew")

        # create textbox
        if sys.platform.startswith("win"):
            self.cipher_textbox = customtkinter.CTkTextbox(
                self.cipher_frame, font=("Consolas", 12), state="disabled")
        else:
            self.cipher_textbox = customtkinter.CTkTextbox(
                self.cipher_frame, font=("DejaVu Sans Mono", 13), state="disabled")
        self.cipher_textbox.grid(row=2, column=0, columnspan=4, padx=(
            20, 20), pady=(0, 0), sticky="nsew")

        # create block frame
        self.block_frame = customtkinter.CTkFrame(
            self, corner_radius=0, fg_color="transparent")
        # self.block_frame.grid_columnconfigure(0, weight=1)

        # select default frame
        self.select_frame_by_name("info")

        # set default values
        self.appearance_mode_optionmenu.set("System")
        self.scaling_optionemenu.set("100%")
        self.cipher_input_entrymode_button.set("Hex")
        self.cipher_transform_optionmenu.set("Encrypt")
        self.cipher_mode_optionmenu.set("Block")
        # self.cipher_iv_entry.configure(placeholder_text="Disabled")
        # self.cipher_iv_entry.configure(state="disabled")
        self.cipher_output_entrymode_button.set("Hex")

    def on_close(self, event=0):
        self.destroy()

    def start(self):
        self.mainloop()

    def select_frame_by_name(self, name):
        # set button color for selected button
        self.info_button.configure(
            fg_color=("gray75", "gray25") if name == "info" else "transparent")
        self.aes_button.configure(
            fg_color=("gray75", "gray25") if name == "cipher" else "transparent")
        self.chaskey_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.clefia_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.desxl_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.fantomas_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.gost_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.hight_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.itubee_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.kasumi_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.klein_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.katan_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.ktantan_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.lblock_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.lea_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.led_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.mantis_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.mcrypton_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.midori_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.misty1_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")

        # show selected frame
        if name == "info":
            self.info_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.info_frame.grid_forget()
        if name == "cipher":
            self.cipher_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.cipher_frame.grid_forget()
        if name == "block":
            self.block_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.block_frame.grid_forget()

    def info_button_event(self):
        self.select_frame_by_name("info")

    def cipher_button_event(self):
        self.select_frame_by_name("cipher")

    def block_button_event(self):
        self.select_frame_by_name("block")

    def change_appearance_mode_optionmenu_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        # customtkinter.deactivate_automatic_dpi_awareness()
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)
        # customtkinter.set_window_scaling(new_scaling_float)

    # cipher
    def change_cipher_transform_optionmenu_event(self, new_transform_optionmenu: str):
        if "Decrypt" == new_transform_optionmenu:
            self.cipher_input_entry.configure(placeholder_text="Ciphertext")
            self.cipher_output_entry.configure(placeholder_text="Plaintext")
        else:
            self.cipher_input_entry.configure(placeholder_text="Plaintext")
            self.cipher_output_entry.configure(placeholder_text="Ciphertext")

    def change_cipher_input_entrymode_button_event(self, new_entrymode: str):
        input_entry = self.cipher_input_entry.get()
        key_entry = self.cipher_key_entry.get()
        if "Hex" == new_entrymode:
            if input_entry:
                self.cipher_input_entry.delete("0", "end")
                self.cipher_input_entry.insert(
                    "insert", input_entry.encode("utf-8").hex())
            if key_entry:
                self.cipher_key_entry.delete("0", "end")
                self.cipher_key_entry.insert(
                    "insert", key_entry.encode("utf-8").hex())
        else:
            if input_entry:
                self.cipher_input_entry.delete("0", "end")
                self.cipher_input_entry.insert(
                    "insert", bytes.fromhex(input_entry).decode("utf-8"))
            if key_entry:
                self.cipher_key_entry.delete("0", "end")
                self.cipher_key_entry.insert(
                    "insert", bytes.fromhex(key_entry).decode("utf-8"))

    def change_cipher_mode_optionmenu_event(self, new_mode_optionmenu: str):
        if "Block" == new_mode_optionmenu or "ECB" == new_mode_optionmenu:
            # self.cipher_iv_entry.delete("0", "end")
            # self.cipher_iv_entry.configure(placeholder_text="Disabled")
            # self.cipher_iv_entry.configure(state="disabled")
            self.cipher_iv_entry.grid_forget()
            # self.cipher_key_entry.grid_forget()
            self.cipher_key_entry.grid(columnspan=2)
        else:
            # self.cipher_iv_entry.configure(state="normal")
            # self.cipher_iv_entry.configure(placeholder_text="Initialization Vector")
            # self.cipher_key_entry.grid_forget()
            self.cipher_key_entry.grid(columnspan=1)
            self.cipher_iv_entry.grid(row=1, column=2, padx=(
                20, 0), pady=(10, 20), sticky="nsew")

    def change_cipher_output_entrymode_button_event(self, new_entrymode: str):
        output_entry = self.cipher_output_entry.get()
        if output_entry:
            self.cipher_output_entry.delete("0", "end")
            if "Hex" == new_entrymode:
                self.cipher_output_entry.insert(
                    "insert", output_entry.encode("utf-8").hex())
            else:
                self.cipher_output_entry.insert(
                    "insert", bytes.fromhex(output_entry).decode("utf-8"))

    def change_cipher_start_button_event(self):
        if "Hex" != self.cipher_input_entrymode_button.get():
            self.cipher_input_entrymode_button.set("Hex")
            self.change_cipher_input_entrymode_button_event("Hex")

        ciphers_folder = "ciphers/"
        exec_cipher = "aes"
        exec_file = "aes.py"
        # exec_output_file_name = exec_file.split(".")[0] + ".txt"
        exec_output_file_name = "output.txt"

        cipher_transform = self.cipher_transform_optionmenu.get(
        ).lower() + "_" + self.cipher_mode_optionmenu.get().lower()

        if sys.platform.startswith("win"):
            exec_stdout = subprocess.check_output(["python", ciphers_folder + exec_cipher + "\\" +
                                                  exec_file, cipher_transform, self.cipher_input_entry.get(), self.cipher_key_entry.get()])
        else:
            exec_stdout = subprocess.check_output(
                [ciphers_folder + exec_cipher + "/" + exec_file, cipher_transform, self.cipher_input_entry.get(), self.cipher_key_entry.get()])

        with open(exec_output_file_name, "r") as exec_output_file:
            exec_output_content = exec_output_file.read()
        exec_output_file.close()

        self.cipher_textbox.configure(state="normal")
        self.cipher_textbox.delete("0.0", "end")
        self.cipher_textbox.insert("insert", exec_output_content)
        self.cipher_textbox.configure(state="disabled")

        self.cipher_output_entry.delete("0", "end")
        self.cipher_output_entrymode_button.set("Hex")
        self.cipher_output_entry.insert("insert", exec_stdout)
        # print(self.cipher_textbox.get("0.0", "insert"))


if __name__ == "__main__":
    # Modes: "System" (standard), "Dark", "Light"
    customtkinter.set_appearance_mode("system")

    # Themes: "blue" (standard), "green", "dark-blue"
    customtkinter.set_default_color_theme("blue")
    # customtkinter.set_default_color_theme(os.path.join(os.path.dirname(
    #     os.path.realpath(__file__)), "assets", "themes", "kou-green.json"))

    customtkinter.set_widget_scaling(int(200)/100)
    # customtkinter.set_window_scaling(int(100)/100)

    app = CipherScope()
    app.start()
