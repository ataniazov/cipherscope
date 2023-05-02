import customtkinter
import sys
import os
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
        # self.createcommand('tk::mac::Quit', self.on_close)

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
        self.large_image = customtkinter.CTkImage(Image.open(
            os.path.join(image_path, "large_image.png")), size=(500, 150))
        self.image_icon_image = customtkinter.CTkImage(Image.open(
            os.path.join(image_path, "image_icon_light.png")), size=(20, 20))
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

        self.navigation_frame_label = customtkinter.CTkLabel(self.navigation_frame, text="  CipherScope", image=self.logo_image,
                                                             compound="left", font=customtkinter.CTkFont(size=18, weight="bold"))
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
        self.appearance_mode_menu = customtkinter.CTkOptionMenu(self.navigation_frame, values=["System", "Light", "Dark"],
                                                                command=self.change_appearance_mode_event)
        self.appearance_mode_menu.grid(
            row=3, column=0, padx=0, pady=(0, 5), sticky="s")

        self.scaling_label = customtkinter.CTkLabel(
            self.navigation_frame, text="UI Scaling:", anchor="w")
        self.scaling_label.grid(row=4, column=0, padx=0,
                                pady=(5, 0), sticky="s")
        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self.navigation_frame, values=["80%", "90%", "100%", "110%", "120%", "200%"],
                                                               command=self.change_scaling_event)
        self.scaling_optionemenu.grid(
            row=5, column=0, padx=0, pady=(0, 20), sticky="s")

        # create buttons in scrollable frame
        self.info_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="CipherScope",
                                                   fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                   image=self.info_image, anchor="w", command=self.info_button_event)
        self.info_button.grid(row=1, column=0, sticky="ew")

        self.aes_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="AES",
                                                  fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                  image=self.block_image, anchor="w", command=self.aes_button_event)
        self.aes_button.grid(row=2, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=3, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=4, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=5, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=6, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=7, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=8, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=9, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=10, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=11, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=12, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=13, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=14, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=15, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=16, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=17, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=18, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=19, column=0, sticky="ew")

        self.block_button = customtkinter.CTkButton(self.scrollable_frame, corner_radius=0, height=40, border_spacing=10, text="Block",
                                                    fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                    image=self.block_image, anchor="w", command=self.block_button_event)
        self.block_button.grid(row=20, column=0, sticky="ew")

        # create info frame
        # self.info_frame = customtkinter.CTkFrame(
        #     self, corner_radius=0, fg_color="transparent")
        self.info_frame = customtkinter.CTkFrame(
            self, corner_radius=0)
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

        # create AES frame
        self.aes_frame = customtkinter.CTkFrame(
            self, corner_radius=0)
        self.aes_frame.grid_rowconfigure(1, weight=1)
        self.aes_frame.grid_columnconfigure((1, 2), weight=1)

        # create main entry and button
        self.aes_entrymode_button = customtkinter.CTkSegmentedButton(
            self.aes_frame, values=["Text", "Hex"], command=self.change_aes_entrymode_button_event)
        self.aes_entrymode_button.grid(row=0, column=0, padx=(
            20, 0), pady=(20, 20), sticky="nsew")

        self.aes_input_entry = customtkinter.CTkEntry(
            self.aes_frame, placeholder_text="Plaintext")
        self.aes_input_entry.grid(row=0, column=1, padx=(
            20, 0), pady=(20, 20), sticky="nsew")

        self.aes_key_entry = customtkinter.CTkEntry(
            self.aes_frame, placeholder_text="Key")
        self.aes_key_entry.grid(row=0, column=2, padx=(
            20, 0), pady=(20, 20), sticky="nsew")

        self.aes_optionmenu = customtkinter.CTkOptionMenu(self.aes_frame, dynamic_resizing=False,
                                                          values=["Encrypt", "Decrypt"], command=self.change_aes_optionmenu_event)
        self.aes_optionmenu.grid(row=0, column=3, padx=(20, 0), pady=(20, 20))

        self.aes_start_button = customtkinter.CTkButton(self.aes_frame, text="Start", fg_color="transparent", border_width=2, hover_color=(
            "#3B8ED0", "#1F6AA5"), text_color=("gray10", "#DCE4EE"), command=self.change_aes_start_button_event)
        # self.aes_start_button = customtkinter.CTkButton(
        #     self.aes_frame, text="Start")
        self.aes_start_button.grid(row=0, column=4, padx=(
            20, 20), pady=(20, 20), sticky="nsew")

        self.aes_output_entrymode_button = customtkinter.CTkSegmentedButton(
            self.aes_frame, values=["Text", "Hex"], command=self.change_aes_output_entrymode_button_event)
        self.aes_output_entrymode_button.grid(row=2, column=0, padx=(
            20, 0), pady=(20, 20), sticky="nsew")

        self.aes_output_entry = customtkinter.CTkEntry(
            self.aes_frame, placeholder_text="Ciphertext")
        self.aes_output_entry.grid(row=2, column=1, columnspan=4, padx=(
            20, 20), pady=(20, 20), sticky="nsew")

        # create textbox
        self.aes_textbox = customtkinter.CTkTextbox(
            self.aes_frame, state="disabled")
        self.aes_textbox.grid(row=1, column=0, columnspan=5, padx=(
            20, 20), pady=(0, 0), sticky="nsew")

        # create block frame
        self.block_frame = customtkinter.CTkFrame(
            self, corner_radius=0, fg_color="transparent")
        # self.block_frame.grid_columnconfigure(0, weight=1)

        # select default frame
        self.select_frame_by_name("info")

        # set default values
        self.appearance_mode_menu.set("System")
        self.scaling_optionemenu.set("100%")
        self.aes_entrymode_button.set("Text")
        self.aes_optionmenu.set("Encrypt")
        self.aes_output_entrymode_button.set("Text")

    def on_close(self, event=0):
        self.destroy()

    def start(self):
        self.mainloop()

    def select_frame_by_name(self, name):
        # set button color for selected button
        self.info_button.configure(
            fg_color=("gray75", "gray25") if name == "info" else "transparent")
        self.aes_button.configure(
            fg_color=("gray75", "gray25") if name == "aes" else "transparent")
        self.block_button.configure(
            fg_color=("gray75", "gray25") if name == "block" else "transparent")

        # show selected frame
        if name == "info":
            self.info_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.info_frame.grid_forget()
        if name == "aes":
            self.aes_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.aes_frame.grid_forget()
        if name == "block":
            self.block_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.block_frame.grid_forget()

    def info_button_event(self):
        self.select_frame_by_name("info")

    def aes_button_event(self):
        self.select_frame_by_name("aes")

    def block_button_event(self):
        self.select_frame_by_name("block")

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        # customtkinter.deactivate_automatic_dpi_awareness()
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)
        # customtkinter.set_window_scaling(new_scaling_float)

    # AES
    def change_aes_optionmenu_event(self, new_optionmenu: str):
        if "Decrypt" == new_optionmenu:
            self.aes_input_entry.configure(placeholder_text="Ciphertext")
            self.aes_output_entry.configure(placeholder_text="Plaintext")
        else:
            self.aes_input_entry.configure(placeholder_text="Plaintext")
            self.aes_output_entry.configure(placeholder_text="Ciphertext")

    def change_aes_entrymode_button_event(self, new_entrymode: str):
        input_entry = self.aes_input_entry.get()
        key_entry = self.aes_key_entry.get()
        if "Hex" == new_entrymode:
            if input_entry:
                self.aes_input_entry.delete("0", "end")
                self.aes_input_entry.insert(
                    "insert", input_entry.encode('utf-8').hex())
            if key_entry:
                self.aes_key_entry.delete("0", "end")
                self.aes_key_entry.insert(
                    "insert", key_entry.encode('utf-8').hex())
        else:
            if input_entry:
                self.aes_input_entry.delete("0", "end")
                self.aes_input_entry.insert(
                    "insert", bytes.fromhex(input_entry).decode('utf-8'))
            if key_entry:
                self.aes_key_entry.delete("0", "end")
                self.aes_key_entry.insert(
                    "insert", bytes.fromhex(key_entry).decode('utf-8'))

    def change_aes_output_entrymode_button_event(self, new_entrymode: str):
        output_entry = self.aes_output_entry.get()
        if output_entry:
            self.aes_output_entry.delete("0", "end")
            if "Hex" == new_entrymode:
                self.aes_output_entry.insert(
                    "insert", output_entry.encode('utf-8').hex())
            else:
                self.aes_output_entry.insert(
                    "insert", bytes.fromhex(output_entry).decode('utf-8'))

    def change_aes_start_button_event(self):
        self.aes_textbox.configure(state="normal")
        self.aes_textbox.delete("0.0", "end")
        self.aes_textbox.insert("insert", "Start")
        self.aes_textbox.configure(state="disabled")
        print(self.aes_textbox.get("0.0", "insert"))


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
