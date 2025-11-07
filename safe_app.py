import customtkinter as ctk
from tkinter import filedialog
import os
import threading # To prevent the GUI from freezing
import steganography_engine as engine # Import our "brain"

# --- 1. Set the App's Appearance ---
ctk.set_appearance_mode("light")  
ctk.set_default_color_theme("blue")

# --- 2. Create the Main App Class ---
class DigitalSafeApp(ctk.CTk):
    def __init__(self):
        # super().__init__() calls the ctk.CTk constructor
        super().__init__()

        # --- Configure the Main Window ---
        self.title("Digital Safe v2.0")
        self.geometry("700x500")
        self.minsize(600, 400)

        # --- Class variables to store paths ---
        self.cover_image_path = ""
        self.secret_file_path = ""
        self.secret_image_decode_path = "" # For the decode tab

        # --- Create the Tabbed Interface ---
        self.tab_view = ctk.CTkTabview(self, anchor="w")
        self.tab_view.pack(pady=10, padx=10, fill="both", expand=True)

        # --- Create the Tabs ---
        self.encode_tab = self.tab_view.add("🔐 Encode")
        self.decode_tab = self.tab_view.add("🔑 Decode")
        
        # --- 4. Add Widgets to the Tabs ---
        self.create_encode_widgets()
        self.create_decode_widgets() 

    # ==================================================================
    # --- ENCODE TAB WIDGETS AND FUNCTIONS ---
    # ==================================================================

    def create_encode_widgets(self):
        """Builds all the widgets for the 'Encode' tab."""
        
        cover_frame = ctk.CTkFrame(self.encode_tab, fg_color="transparent")
        cover_frame.pack(fill="x", padx=10, pady=10)

        cover_label = ctk.CTkLabel(cover_frame, text="1. Select Cover Image:", font=ctk.CTkFont(size=14))
        cover_label.pack(side="left")
        
        cover_btn = ctk.CTkButton(
            cover_frame, text="Browse", width=100, command=self.select_cover_image
        )
        cover_btn.pack(side="right", padx=10)

        self.cover_file_label = ctk.CTkLabel(
            cover_frame, text="No file selected.", 
            font=ctk.CTkFont(size=12, slant="italic"),
            text_color="gray"
        )
        self.cover_file_label.pack(side="right", fill="x", expand=True, padx=10)
        
        secret_frame = ctk.CTkFrame(self.encode_tab, fg_color="transparent")
        secret_frame.pack(fill="x", padx=10, pady=10)

        secret_label = ctk.CTkLabel(secret_frame, text="2. Select Secret File:", font=ctk.CTkFont(size=14))
        secret_label.pack(side="left")
        
        secret_btn = ctk.CTkButton(
            secret_frame, text="Browse", width=100, command=self.select_secret_file
        )
        secret_btn.pack(side="right", padx=10)

        self.secret_file_label = ctk.CTkLabel(
            secret_frame, text="No file selected.", 
            font=ctk.CTkFont(size=12, slant="italic"),
            text_color="gray"
        )
        self.secret_file_label.pack(side="right", fill="x", expand=True, padx=10)

        pass_frame = ctk.CTkFrame(self.encode_tab, fg_color="transparent")
        pass_frame.pack(fill="x", padx=10, pady=10)

        pass_label = ctk.CTkLabel(pass_frame, text="3. Enter Password:   ", font=ctk.CTkFont(size=14))
        pass_label.pack(side="left")

        self.encode_pass_entry = ctk.CTkEntry(
            pass_frame, placeholder_text="Enter a strong password...", show="*"
        )
        self.encode_pass_entry.pack(fill="x", expand=True, side="left")

        self.encode_btn = ctk.CTkButton(
            self.encode_tab, text="HIDE FILE",
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self.start_encoding_thread
        )
        self.encode_btn.pack(fill="x", padx=10, pady=20, ipady=10) 

        self.encode_status_label = ctk.CTkLabel(
            self.encode_tab, text="Ready to encode...",
            font=ctk.CTkFont(size=12)
        )
        self.encode_status_label.pack(side="bottom", fill="x", padx=10, pady=10)

    def select_cover_image(self):
        filetypes = (('Image files', '*.png *.jpg *.jpeg *.bmp'), ('All files', '*.*'))
        path = filedialog.askopenfilename(title='Select a Cover Image', filetypes=filetypes)
        if path:
            self.cover_image_path = path
            filename = os.path.basename(path)
            self.cover_file_label.configure(text=filename, text_color_disabled="black")

    def select_secret_file(self):
        path = filedialog.askopenfilename(title='Select a Secret File')
        if path:
            self.secret_file_path = path
            filename = os.path.basename(path)
            self.secret_file_label.configure(text=filename, text_color_disabled="black")

    def start_encoding_thread(self):
        self.encode_btn.configure(state="disabled", text="ENCODING...")
        self.encode_status_label.configure(text="Starting...", text_color="gray")
        threading.Thread(target=self.start_encoding, daemon=True).start()

    def start_encoding(self):
        password = self.encode_pass_entry.get()
        
        if not self.cover_image_path:
            self.encode_status_label.configure(text="Error: Please select a cover image.", text_color="red")
            self.encode_btn.configure(state="normal", text="HIDE FILE") 
            return
        if not self.secret_file_path:
            self.encode_status_label.configure(text="Error: Please select a secret file.", text_color="red")
            self.encode_btn.configure(state="normal", text="HIDE FILE")
            return
        if not password:
            self.encode_status_label.configure(text="Error: Please enter a password.", text_color="red")
            self.encode_btn.configure(state="normal", text="HIDE FILE")
            return

        try:
            self.encode_status_label.configure(text="Processing and encrypting file...", text_color="gray")
            bit_stream = engine.get_secret_bit_stream(self.secret_file_path, password)
            if bit_stream is None:
                raise Exception("Could not read or encrypt file.")
            
            self.encode_status_label.configure(text="Checking image capacity...", text_color="gray")
            bits_to_hide = len(bit_stream)
            if not engine.check_image_capacity(self.cover_image_path, bits_to_hide):
                raise Exception(f"Image is too small. Needs {bits_to_hide} bits.")

            self.after(0, self.ask_save_path_and_encode, bit_stream)
            
        except Exception as e:
            self.encode_status_label.configure(text=f"Error: {e}", text_color="red")
            self.encode_btn.configure(state="normal", text="HIDE FILE")

    def ask_save_path_and_encode(self, bit_stream):
        save_path = filedialog.asksaveasfilename(
            title="Save Encoded Image As",
            defaultextension=".png",
            filetypes=(("PNG files", "*.png"),)
        )
        if not save_path:
            self.encode_status_label.configure(text="Encode cancelled.", text_color="orange")
            self.encode_btn.configure(state="normal", text="HIDE FILE")
            return

        try:
            self.encode_status_label.configure(text="Encoding... this may take a moment.", text_color="gray")
            success = engine.hide_data_in_image(
                self.cover_image_path, 
                bit_stream, 
                save_path
            )
            
            if success:
                self.encode_status_label.configure(text=f"Success! File hidden in {os.path.basename(save_path)}", text_color="green")
            else:
                raise Exception("Encoding failed. See terminal for details.")
                
        except Exception as e:
            self.encode_status_label.configure(text=f"Error: {e}", text_color="red")
        
        self.encode_btn.configure(state="normal", text="HIDE FILE")

    # ==================================================================
    # --- DECODE TAB WIDGETS AND FUNCTIONS (ALL NEW!) ---
    # ==================================================================

    def create_decode_widgets(self):
        """Builds all the widgets for the 'Decode' tab."""
        
        # --- 1. Secret Image Frame ---
        secret_img_frame = ctk.CTkFrame(self.decode_tab, fg_color="transparent")
        secret_img_frame.pack(fill="x", padx=10, pady=10)

        secret_img_label = ctk.CTkLabel(secret_img_frame, text="1. Select Secret Image:", font=ctk.CTkFont(size=14))
        secret_img_label.pack(side="left")
        
        secret_img_btn = ctk.CTkButton(
            secret_img_frame, 
            text="Browse",
            width=100,
            command=self.select_secret_image_for_decode
        )
        secret_img_btn.pack(side="right", padx=10)

        self.secret_image_decode_label = ctk.CTkLabel(
            secret_img_frame, 
            text="No file selected.", 
            font=ctk.CTkFont(size=12, slant="italic"),
            text_color="gray"
        )
        self.secret_image_decode_label.pack(side="right", fill="x", expand=True, padx=10)

        # --- 2. Password Frame ---
        pass_frame = ctk.CTkFrame(self.decode_tab, fg_color="transparent")
        pass_frame.pack(fill="x", padx=10, pady=10)

        pass_label = ctk.CTkLabel(pass_frame, text="2. Enter Password:   ", font=ctk.CTkFont(size=14))
        pass_label.pack(side="left")

        self.decode_pass_entry = ctk.CTkEntry(
            pass_frame, 
            placeholder_text="Enter the password...",
            show="*"
        )
        self.decode_pass_entry.pack(fill="x", expand=True, side="left")

        # --- 3. Main "DECODE" Button ---
        self.decode_btn = ctk.CTkButton(
            self.decode_tab, 
            text="EXTRACT FILE",
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self.start_decoding_thread
        )
        self.decode_btn.pack(fill="x", padx=10, pady=20, ipady=10) 

        # --- 4. Status Bar ---
        self.decode_status_label = ctk.CTkLabel(
            self.decode_tab, 
            text="Ready to decode...",
            font=ctk.CTkFont(size=12)
        )
        self.decode_status_label.pack(side="bottom", fill="x", padx=10, pady=10)

    def select_secret_image_for_decode(self):
        """Opens a file dialog to select the image to decode."""
        filetypes = (('PNG files', '*.png'), ('All files', '*.*')) 
        path = filedialog.askopenfilename(title='Select a Secret Image', filetypes=filetypes)
        if path:
            self.secret_image_decode_path = path
            filename = os.path.basename(path)
            self.secret_image_decode_label.configure(text=filename, text_color_disabled="black")

    def start_decoding_thread(self):
        """Starts the decoding in a separate thread."""
        self.decode_btn.configure(state="disabled", text="EXTRACTING...")
        self.decode_status_label.configure(text="Starting...", text_color="gray")
        threading.Thread(target=self.start_decoding, daemon=True).start()

    def start_decoding(self):
        """The actual decoding logic that runs in the thread."""
        
        password = self.decode_pass_entry.get()
        
        if not self.secret_image_decode_path:
            self.decode_status_label.configure(text="Error: Please select a secret image.", text_color="red")
            self.decode_btn.configure(state="normal", text="EXTRACT FILE")
            return
        if not password:
            self.decode_status_label.configure(text="Error: Please enter a password.", text_color="red")
            self.decode_btn.configure(state="normal", text="EXTRACT FILE")
            return

        # --- Ask where to save the *extracted* file ---
        # We must run this on the main thread
        self.after(0, self.ask_save_path_and_decode, password)

    def ask_save_path_and_decode(self, password):
        """Asks where to save the extracted file, then runs the engine."""
        save_path = filedialog.asksaveasfilename(
            title="Save Secret File As",
            defaultextension=".*",
            filetypes=(("All files", "*.*"),)
        )
        if not save_path:
            self.decode_status_label.configure(text="Decode cancelled.", text_color="orange")
            self.decode_btn.configure(state="normal", text="EXTRACT FILE")
            return
        
        # --- Call the "Brain" ---
        try:
            self.decode_status_label.configure(text="Extracting and decrypting...", text_color="gray")
            
            result = engine.extract_data_from_image(
                self.secret_image_decode_path,
                save_path,
                password
            )
            
            if result == "success":
                self.decode_status_label.configure(text=f"Success! File extracted to {os.path.basename(save_path)}", text_color="green")
            elif result == "password_error":
                self.decode_status_label.configure(text="Error: WRONG PASSWORD or corrupt file.", text_color="red")
            else:
                self.decode_status_label.configure(text="Error: Extraction failed. No data found.", text_color="red")
        
        except Exception as e:
            self.decode_status_label.configure(text=f"Error: {e}", text_color="red")

        self.decode_btn.configure(state="normal", text="EXTRACT FILE")


# --- 3. Run the Application ---
if __name__ == "__main__":
    app = DigitalSafeApp()
    app.mainloop()