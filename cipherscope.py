#!/usr/bin/env python3

import customtkinter
import sys
import os
import subprocess
from PIL import Image


class MessageBox(customtkinter.CTkToplevel):
    WINDOW_NAME = "Message Box"
    WIDTH = 500
    HEIGHT = 200

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # configure window
        self.title(self.WINDOW_NAME)

        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.minsize(self.WIDTH, self.HEIGHT)
        self.resizable(width=False, height=False)

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.bind("<Control-q>", self.on_close)
        self.bind("<Control-w>", self.on_close)
        # self.createcommand("tk::mac::Quit", self.on_close)

        # set grid layout 1x2
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.button = customtkinter.CTkButton(
            self, text="OK", command=self.on_close)
        self.button.grid(row=1, column=0, padx=(
            80, 80), pady=(10, 20), sticky="nsew")

    def on_close(self, event=0):
        self.destroy()

    def setMessage(self, message: str):
        self.label = customtkinter.CTkLabel(self, text=message)
        self.label.grid(row=0, column=0, padx=(20, 20),
                        pady=(20, 10), sticky="nsew")


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
        # self.resizable(width=False, height=False)

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.bind("<Control-q>", self.on_close)
        self.bind("<Control-w>", self.on_close)
        # self.createcommand("tk::mac::Quit", self.on_close)

        # Message top level window
        self.messagebox = None

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
                                                  image=self.block_image, anchor="w", command=self.aes_button_event)
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
                                                    image=self.block_image, anchor="w", command=self.desxl_button_event)
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

        ##################
        #  Cipher Frame  #
        ##################

        # create cipher frame
        self.cipher_frame = customtkinter.CTkFrame(self, corner_radius=0)
        self.cipher_frame.grid_rowconfigure(2, weight=1)
        self.cipher_frame.grid_columnconfigure((1, 2), weight=1)

        # create main entry and button
        self.cipher_input_entrymode_button = customtkinter.CTkSegmentedButton(self.cipher_frame, values=[
                                                                              "Hex", "Text", "Bin"], command=self.change_cipher_input_entrymode_button_event)
        self.cipher_input_entrymode_button.grid(
            row=0, column=0, padx=(20, 0), pady=(20, 10), sticky="nsew")

        self.cipher_text_input_entry = customtkinter.CTkEntry(
            self.cipher_frame, placeholder_text="Plaintext")
        self.cipher_text_input_entry.grid(
            row=0, column=1, columnspan=2, padx=(20, 0), pady=(20, 10), sticky="nsew")

        self.cipher_transform_optionmenu = customtkinter.CTkOptionMenu(self.cipher_frame, dynamic_resizing=False, values=[
                                                                       "Encrypt", "Decrypt"], command=self.change_cipher_transform_optionmenu_event)
        self.cipher_transform_optionmenu.grid(
            row=0, column=3, padx=(20, 20), pady=(20, 10))

        self.cipher_mode_optionmenu = customtkinter.CTkOptionMenu(self.cipher_frame, dynamic_resizing=False, values=[
                                                                  "Block", "ECB", "CTR"], command=self.change_cipher_mode_optionmenu_event)
        self.cipher_mode_optionmenu.grid(
            row=1, column=0, padx=(20, 0), pady=(10, 20))

        self.cipher_key_input_entry = customtkinter.CTkEntry(
            self.cipher_frame, placeholder_text="Cipher Key")
        self.cipher_key_input_entry.grid(row=1, column=1, columnspan=2, padx=(
            20, 0), pady=(10, 20), sticky="nsew")

        self.cipher_iv_input_entry = customtkinter.CTkEntry(
            self.cipher_frame, placeholder_text="Initialization Vector")
        # self.cipher_iv_input_entry.grid(row=1, column=2, padx=(20, 0), pady=(10, 20), sticky="nsew")

        self.cipher_start_button = customtkinter.CTkButton(self.cipher_frame, text="Start", fg_color="transparent", border_width=2, hover_color=(
            "#3B8ED0", "#1F6AA5"), text_color=("gray10", "#DCE4EE"), command=self.change_cipher_start_button_event)
        # self.cipher_start_button = customtkinter.CTkButton(
        #     self.cipher_frame, text="Start")
        self.cipher_start_button.grid(row=1, column=3, padx=(
            20, 20), pady=(10, 20), sticky="nsew")

        self.cipher_pre_whitening_input_entry = customtkinter.CTkEntry(
            self.cipher_frame, placeholder_text="Pre-Whitening Key")
        # self.cipher_pre_whitening_input_entry.grid(row=2, column=0, padx=(20, 0), pady=(10, 20), sticky="nsew")

        self.cipher_post_whitening_input_entry = customtkinter.CTkEntry(
            self.cipher_frame, placeholder_text="Post-Whitening Key")
        # self.cipher_pre_whitening_input_entry.grid(row=2, column=1, padx=(20, 0), pady=(10, 20), sticky="nsew")

        self.cipher_output_entrymode_button = customtkinter.CTkSegmentedButton(self.cipher_frame, values=[
                                                                               "Hex", "Text", "Bin"], command=self.change_cipher_output_entrymode_button_event)
        self.cipher_output_entrymode_button.grid(
            row=3, column=0, padx=(20, 0), pady=(20, 20), sticky="nsew")

        self.cipher_text_output_entry = customtkinter.CTkEntry(
            self.cipher_frame, placeholder_text="Ciphertext")
        self.cipher_text_output_entry.grid(row=3, column=1, columnspan=3, padx=(
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

        # set default values
        self.cipher_input_entrymode_button.set("Hex")
        self.cipher_transform_optionmenu.set("Encrypt")
        self.cipher_mode_optionmenu.set("Block")
        # self.cipher_iv_input_entry.configure(placeholder_text="Disabled")
        # self.cipher_iv_input_entry.configure(state="disabled")
        self.cipher_output_entrymode_button.set("Hex")

        #########################
        #  End of Cipher Frame  #
        #########################

        # create block frame
        self.block_frame = customtkinter.CTkFrame(
            self, corner_radius=0, fg_color="transparent")
        # self.block_frame.grid_columnconfigure(0, weight=1)

        # select default frame
        self.select_frame_by_name("info")

        # set default values
        self.appearance_mode_optionmenu.set("System")
        self.scaling_optionemenu.set("100%")

    def on_close(self, event=0):
        self.destroy()

    def start(self):
        self.mainloop()

    def open_messagebox(self, message: str):
        if self.messagebox is None or not self.messagebox.winfo_exists():
            self.messagebox = MessageBox(self).setMessage(message)
        else:
            self.messagebox.focus()

    cipher = ""

    def select_frame_by_name(self, name):
        # set button color for selected button
        self.info_button.configure(
            fg_color=("gray75", "gray25") if name == "info" else "transparent")
        self.aes_button.configure(
            fg_color=("gray75", "gray25") if name == "aes" else "transparent")
        self.chaskey_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.clefia_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")
        self.desxl_button.configure(
            fg_color=("gray75", "gray25") if name == "desxl" else "transparent")
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
        if "info" == name:
            self.info_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.info_frame.grid_forget()

        if "aes" == name:
            self.cipher = "aes"

            self.cipher_pre_whitening_input_entry.grid_forget()
            self.cipher_post_whitening_input_entry.grid_forget()

            self.cipher_frame.grid_rowconfigure(3, weight=0)
            self.cipher_frame.grid_rowconfigure(2, weight=1)

            self.cipher_mode_optionmenu.grid(pady=(10, 20))

            if "CTR" == self.cipher_mode_optionmenu.get():
                self.cipher_key_input_entry.grid(columnspan=1, pady=(10, 20))
                self.cipher_iv_input_entry.grid(pady=(10, 20))
            else:
                self.cipher_key_input_entry.grid(columnspan=2, pady=(10, 20))

            self.cipher_start_button.grid(pady=(10, 20))

            self.cipher_textbox.grid(row=2)
            self.cipher_output_entrymode_button.grid(row=3)
            self.cipher_text_output_entry.grid(row=3)

            self.cipher_frame.grid(row=0, column=1, sticky="nsew")
        elif "desxl" == name:
            self.cipher = "desxl"

            self.cipher_frame.grid_rowconfigure(2, weight=0)
            self.cipher_frame.grid_rowconfigure(3, weight=1)

            self.cipher_mode_optionmenu.grid(pady=(10, 10))

            if "ctr" == self.cipher_mode_optionmenu.get().lower():
                self.cipher_key_input_entry.grid(columnspan=1, pady=(10, 10))
                self.cipher_iv_input_entry.grid(pady=(10, 10))
            else:
                self.cipher_key_input_entry.grid(columnspan=2, pady=(10, 10))

            self.cipher_start_button.grid(pady=(10, 10))

            self.cipher_pre_whitening_input_entry.grid(
                row=2, column=0, columnspan=2, padx=(20, 0), pady=(10, 20), sticky="nsew")
            self.cipher_post_whitening_input_entry.grid(
                row=2, column=2, columnspan=2, padx=(20, 20), pady=(10, 20), sticky="nsew")

            self.cipher_textbox.grid(row=3)
            self.cipher_output_entrymode_button.grid(row=4)
            self.cipher_text_output_entry.grid(row=4)

            self.cipher_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.cipher_frame.grid_forget()

        if "block" == name:
            self.block_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.block_frame.grid_forget()

    def info_button_event(self):
        self.select_frame_by_name("info")

    def aes_button_event(self):
        self.select_frame_by_name("aes")

    def desxl_button_event(self):
        self.select_frame_by_name("desxl")

    def block_button_event(self):
        self.select_frame_by_name("block")

    def change_appearance_mode_optionmenu_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        # customtkinter.deactivate_automatic_dpi_awareness()
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)
        # customtkinter.set_window_scaling(new_scaling_float)

    ###################
    #  Cipher Events  #
    ###################
    # cipher
    def change_cipher_transform_optionmenu_event(self, new_transform_optionmenu: str):
        if "Decrypt" == new_transform_optionmenu:
            self.cipher_text_input_entry.configure(
                placeholder_text="Ciphertext")
            self.cipher_text_output_entry.configure(
                placeholder_text="Plaintext")
        else:
            self.cipher_text_input_entry.configure(
                placeholder_text="Plaintext")
            self.cipher_text_output_entry.configure(
                placeholder_text="Ciphertext")

    previous_cipher_input_entrymode = "Hex"

    def change_cipher_input_entrymode_button_event(self, new_input_entrymode: str):
        text_input_entry = self.cipher_text_input_entry.get()
        key_input_entry = self.cipher_key_input_entry.get()

        # if "desxl" == self.cipher:
        pre_whitening_input_entry = self.cipher_pre_whitening_input_entry.get()
        post_whitening_input_entry = self.cipher_post_whitening_input_entry.get()
        # else:
        #     pre_whitening_input_entry = ""
        #     post_whitening_input_entry = ""

        if "Hex" == new_input_entrymode:
            if "Text" == self.previous_cipher_input_entrymode:
                if text_input_entry:
                    self.cipher_text_input_entry.delete("0", "end")
                    self.cipher_text_input_entry.insert(
                        "insert", text_input_entry.encode("utf-8").hex())
                if key_input_entry:
                    self.cipher_key_input_entry.delete("0", "end")
                    self.cipher_key_input_entry.insert(
                        "insert", key_input_entry.encode("utf-8").hex())
                if pre_whitening_input_entry:
                    self.cipher_pre_whitening_input_entry.delete("0", "end")
                    self.cipher_pre_whitening_input_entry.insert(
                        "insert", pre_whitening_input_entry.encode("utf-8").hex())
                if post_whitening_input_entry:
                    self.cipher_post_whitening_input_entry.delete("0", "end")
                    self.cipher_post_whitening_input_entry.insert(
                        "insert", post_whitening_input_entry.encode("utf-8").hex())
            elif "Bin" == self.previous_cipher_input_entrymode:
                if text_input_entry:
                    self.cipher_text_input_entry.delete("0", "end")
                    self.cipher_text_input_entry.insert(
                        "insert", hex(int(text_input_entry, 2))[2:])
                if key_input_entry:
                    self.cipher_key_input_entry.delete("0", "end")
                    self.cipher_key_input_entry.insert(
                        "insert", hex(int(key_input_entry, 2))[2:])
                if pre_whitening_input_entry:
                    self.cipher_pre_whitening_input_entry.delete("0", "end")
                    self.cipher_pre_whitening_input_entry.insert(
                        "insert", hex(int(pre_whitening_input_entry, 2))[2:])
                if post_whitening_input_entry:
                    self.cipher_post_whitening_input_entry.delete("0", "end")
                    self.cipher_post_whitening_input_entry.insert(
                        "insert", hex(int(post_whitening_input_entry, 2))[2:])

        elif "Text" == new_input_entrymode:
            if "Hex" == self.previous_cipher_input_entrymode:
                if text_input_entry:
                    self.cipher_text_input_entry.delete("0", "end")
                    self.cipher_text_input_entry.insert(
                        "insert", bytes.fromhex(text_input_entry).decode("utf-8"))
                if key_input_entry:
                    self.cipher_key_input_entry.delete("0", "end")
                    self.cipher_key_input_entry.insert(
                        "insert", bytes.fromhex(key_input_entry).decode("utf-8"))
                if pre_whitening_input_entry:
                    self.cipher_pre_whitening_input_entry.delete("0", "end")
                    self.cipher_pre_whitening_input_entry.insert(
                        "insert", bytes.fromhex(pre_whitening_input_entry).decode("utf-8"))
                if post_whitening_input_entry:
                    self.cipher_post_whitening_input_entry.delete("0", "end")
                    self.cipher_post_whitening_input_entry.insert(
                        "insert", bytes.fromhex(post_whitening_input_entry).decode("utf-8"))
            elif "Bin" == self.previous_cipher_input_entrymode:
                if text_input_entry:
                    self.cipher_text_input_entry.delete("0", "end")
                    self.cipher_text_input_entry.insert(
                        "insert", "".join(chr(int(text_input_entry[i:i+8], 2)) for i in range(0, len(text_input_entry), 8)))
                if key_input_entry:
                    self.cipher_key_input_entry.delete("0", "end")
                    self.cipher_key_input_entry.insert(
                        "insert", "".join(chr(int(key_input_entry[i:i+8], 2)) for i in range(0, len(key_input_entry), 8)))
                if pre_whitening_input_entry:
                    self.cipher_pre_whitening_input_entry.delete("0", "end")
                    self.cipher_pre_whitening_input_entry.insert(
                        "insert", "".join(chr(int(pre_whitening_input_entry[i:i+8], 2)) for i in range(0, len(pre_whitening_input_entry), 8)))
                if post_whitening_input_entry:
                    self.cipher_post_whitening_input_entry.delete("0", "end")
                    self.cipher_post_whitening_input_entry.insert(
                        "insert", "".join(chr(int(post_whitening_input_entry[i:i+8], 2)) for i in range(0, len(post_whitening_input_entry), 8)))

        elif "Bin" == new_input_entrymode:
            if "Text" == self.previous_cipher_input_entrymode:
                if text_input_entry:
                    self.cipher_text_input_entry.delete("0", "end")
                    self.cipher_text_input_entry.insert("insert", "".join(
                        format(ord(char), "08b") for char in text_input_entry))
                if key_input_entry:
                    self.cipher_key_input_entry.delete("0", "end")
                    self.cipher_key_input_entry.insert("insert", "".join(
                        format(ord(char), "08b") for char in key_input_entry))
                if pre_whitening_input_entry:
                    self.cipher_pre_whitening_input_entry.delete("0", "end")
                    self.cipher_pre_whitening_input_entry.insert(
                        "insert", "".join(format(ord(char), "08b") for char in pre_whitening_input_entry))
                if post_whitening_input_entry:
                    self.cipher_post_whitening_input_entry.delete("0", "end")
                    self.cipher_post_whitening_input_entry.insert(
                        "insert", "".join(format(ord(char), "08b") for char in post_whitening_input_entry))
            elif "Hex" == self.previous_cipher_input_entrymode:
                if text_input_entry:
                    self.cipher_text_input_entry.delete("0", "end")
                    self.cipher_text_input_entry.insert("insert", "".join(
                        format(int(nibble, 16), '04b') for nibble in text_input_entry))
                if key_input_entry:
                    self.cipher_key_input_entry.delete("0", "end")
                    self.cipher_key_input_entry.insert("insert", "".join(
                        format(int(nibble, 16), '04b') for nibble in key_input_entry))
                if pre_whitening_input_entry:
                    self.cipher_pre_whitening_input_entry.delete("0", "end")
                    self.cipher_pre_whitening_input_entry.insert(
                        "insert", "".join(format(int(nibble, 16), '04b') for nibble in pre_whitening_input_entry))
                if post_whitening_input_entry:
                    self.cipher_post_whitening_input_entry.delete("0", "end")
                    self.cipher_post_whitening_input_entry.insert(
                        "insert", "".join(format(int(nibble, 16), '04b') for nibble in post_whitening_input_entry))

        self.previous_cipher_input_entrymode = new_input_entrymode

    def change_cipher_mode_optionmenu_event(self, new_mode_optionmenu: str):
        if "Block" == new_mode_optionmenu or "ECB" == new_mode_optionmenu:
            # self.cipher_iv_input_entry.delete("0", "end")
            # self.cipher_iv_input_entry.configure(placeholder_text="Disabled")
            # self.cipher_iv_input_entry.configure(state="disabled")
            self.cipher_iv_input_entry.grid_forget()
            # self.cipher_key_input_entry.grid_forget()
            self.cipher_key_input_entry.grid(columnspan=2)
        else:
            # self.cipher_iv_input_entry.configure(state="normal")
            # self.cipher_iv_input_entry.configure(placeholder_text="Initialization Vector")
            # self.cipher_key_input_entry.grid_forget()
            self.cipher_key_input_entry.grid(columnspan=1)

            row_pady = (10, 10) if "desxl" == self.cipher else (10, 20)
            self.cipher_iv_input_entry.grid(
                row=1, column=2, padx=(20, 0), pady=row_pady, sticky="nsew")

    previous_cipher_output_entrymode = "Hex"

    def change_cipher_output_entrymode_button_event(self, new_output_entrymode: str):
        text_output_entry = self.cipher_text_output_entry.get()
        if text_output_entry:
            self.cipher_text_output_entry.delete("0", "end")
            if "Hex" == new_output_entrymode:
                if "Text" == self.previous_cipher_output_entrymode:
                    self.cipher_text_output_entry.insert(
                        "insert", text_output_entry.encode("utf-8").hex())
                elif "Bin" == self.previous_cipher_output_entrymode:
                    self.cipher_text_output_entry.insert(
                        "insert", hex(int(text_output_entry, 2))[2:])
            elif "Text" == new_output_entrymode:
                if "Hex" == self.previous_cipher_output_entrymode:
                    self.cipher_text_output_entry.insert(
                        "insert", bytes.fromhex(text_output_entry).decode("utf-8"))
                elif "Bin" == self.previous_cipher_output_entrymode:
                    self.cipher_text_output_entry.insert(
                        "insert", "".join(chr(int(text_output_entry[i:i+8], 2)) for i in range(0, len(text_output_entry), 8)))
            elif "Bin" == new_output_entrymode:
                if "Text" == self.previous_cipher_output_entrymode:
                    self.cipher_text_output_entry.insert("insert", "".join(
                        format(ord(char), "08b") for char in text_output_entry))
                elif "Hex" == self.previous_cipher_output_entrymode:
                    self.cipher_text_output_entry.insert("insert", "".join(
                        format(int(nibble, 16), '04b') for nibble in text_output_entry))
        self.previous_cipher_output_entrymode = new_output_entrymode

    def change_cipher_start_button_event(self):
        if "Hex" != self.cipher_input_entrymode_button.get():
            self.cipher_input_entrymode_button.set("Hex")
            self.change_cipher_input_entrymode_button_event("Hex")

        ciphers_folder = "ciphers/"
        exec_cipher = self.cipher
        exec_file = exec_cipher + ".py"
        # exec_output_file_name = exec_file.split(".")[0] + ".txt"
        exec_output_file_name = "output.txt"

        cipher_transform = self.cipher_transform_optionmenu.get(
        ).lower() + "_" + self.cipher_mode_optionmenu.get().lower()

        exec_command = []
        if sys.platform.startswith("win"):
            exec_command.extend(
                ["python", ciphers_folder + exec_cipher + "\\" + exec_file])
            # exec_stdout = subprocess.check_output(["python", ciphers_folder + exec_cipher + "\\" +
            #                                       exec_file, cipher_transform, self.cipher_text_input_entry.get(), self.cipher_key_input_entry.get()])
            # exec_command = "python", ciphers_folder + exec_cipher + "\\" + \
            #     exec_file, cipher_transform, self.cipher_text_input_entry.get(
            #     ), self.cipher_key_input_entry.get()
            # exec_stdout = subprocess.check_output(
            #     [ciphers_folder + exec_cipher + "/" + exec_file, cipher_transform, self.cipher_text_input_entry.get(), self.cipher_key_input_entry.get()])
            # exec_command = ciphers_folder + exec_cipher + "/" + \
            #     exec_file, cipher_transform, self.cipher_text_input_entry.get(
            #     ), self.cipher_key_input_entry.get()
        else:
            exec_command.extend(
                ["python3", ciphers_folder + exec_cipher + "/" + exec_file])

        exec_command.extend([cipher_transform, self.cipher_text_input_entry.get(
        ), self.cipher_key_input_entry.get()])

        if "desxl" == exec_cipher:
            exec_command.extend([self.cipher_pre_whitening_input_entry.get(
            ), self.cipher_post_whitening_input_entry.get()])

        if "encrypt_ctr" == cipher_transform or "decrypt_ctr" == cipher_transform:
            exec_command.append(self.cipher_iv_input_entry.get())

        exec_stdout = subprocess.check_output(exec_command)

        with open(exec_output_file_name, "r") as exec_output_file:
            exec_output_content = exec_output_file.read()
        exec_output_file.close()

        self.cipher_textbox.configure(state="normal")
        self.cipher_textbox.delete("0.0", "end")
        self.cipher_textbox.insert("insert", exec_output_content)
        self.cipher_textbox.configure(state="disabled")

        self.cipher_text_output_entry.delete("0", "end")
        self.cipher_output_entrymode_button.set("Hex")
        self.cipher_text_output_entry.insert("insert", exec_stdout)

        ##########################
        #  End of Cipher Events  #
        ##########################


if __name__ == "__main__":
    # Modes: "System" (standard), "Dark", "Light"
    customtkinter.set_appearance_mode("system")

    # Themes: "blue" (standard), "green", "dark-blue"
    customtkinter.set_default_color_theme("blue")
    # customtkinter.set_default_color_theme(os.path.join(os.path.dirname(
    #     os.path.realpath(__file__)), "assets", "themes", "kou-green.json"))

    customtkinter.set_widget_scaling(int(100)/100)
    # customtkinter.set_window_scaling(int(100)/100)

    app = CipherScope()
    app.start()
