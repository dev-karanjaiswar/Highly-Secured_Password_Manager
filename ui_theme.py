import tkinter as tk
from tkinter import ttk
import time
from PIL import Image, ImageTk

# Define a modern color palette
COLORS = {
    "primary": "#2962FF",     # Vibrant blue as primary color
    "secondary": "#FF6D00",   # Orange for accents/buttons
    "background": "#F5F7FA",  # Light gray background
    "card": "#FFFFFF",        # White for card backgrounds
    "text_dark": "#263238",   # Dark text
    "text_light": "#FFFFFF",  # Light text
    "success": "#00C853",     # Green for success messages
    "error": "#D50000",       # Red for errors
    "warning": "#FFD600",     # Yellow for warnings
}

def apply_theme(root):
    """Apply the modern theme to the application"""
    # Create a custom style for the application
    style = ttk.Style()
    style.theme_use("clam")  # Use clam as base theme
    
    # Configure base styles
    style.configure("TFrame", background=COLORS["background"])
    style.configure("TLabel", background=COLORS["background"], foreground=COLORS["text_dark"])
    style.configure("TButton", background=COLORS["primary"], foreground=COLORS["text_light"], 
                   font=("Segoe UI", 10), padding=6)
    style.map("TButton", 
             background=[("active", COLORS["secondary"])],
             foreground=[("active", COLORS["text_light"])])
    
    # Configure treeview for credential displays
    style.configure("Treeview", 
                   background=COLORS["card"],
                   foreground=COLORS["text_dark"],
                   rowheight=30,
                   fieldbackground=COLORS["card"],
                   font=("Segoe UI", 10))
    
    style.configure("Treeview.Heading",
                   background=COLORS["primary"],
                   foreground=COLORS["text_light"],
                   relief="flat",
                   font=("Segoe UI", 11, "bold"))
    
    style.map("Treeview.Heading",
             background=[("active", COLORS["secondary"])])
    
    style.map("Treeview",
             background=[("selected", COLORS["primary"])],
             foreground=[("selected", COLORS["text_light"])])
    
    # Configure entry fields
    style.configure("TEntry", 
                   font=("Segoe UI", 10),
                   padding=10)
    
    # Set app background
    root.configure(bg=COLORS["background"])

def create_card_frame(parent, padding=20):
    """Create a modern card-like frame with shadow effect"""
    # Outer frame for shadow effect
    shadow_frame = tk.Frame(parent, bg="#DDDDDD", padx=2, pady=2)
    shadow_frame.pack(pady=15, padx=15)
    
    # Inner frame for content
    card = tk.Frame(shadow_frame, bg=COLORS["card"], padx=padding, pady=padding)
    card.pack(fill="both", expand=True)
    
    return card

class ModernButton(tk.Button):
    """Custom button with modern styling"""
    def __init__(self, master=None, **kwargs):
        kwargs.update({
            "font": ("Segoe UI", 10),
            "borderwidth": 0,
            "cursor": "hand2",
            "activebackground": COLORS["secondary"],
            "activeforeground": COLORS["text_light"],
            "padx": 15,
            "pady": 8,
            "relief": tk.FLAT
        })
        
        # Primary or secondary button
        if "type" in kwargs:
            if kwargs["type"] == "primary":
                kwargs["bg"] = COLORS["primary"]
                kwargs["fg"] = COLORS["text_light"]
            else:
                kwargs["bg"] = "#EEEEEE"
                kwargs["fg"] = COLORS["text_dark"]
            del kwargs["type"]
        else:
            kwargs["bg"] = COLORS["primary"]
            kwargs["fg"] = COLORS["text_light"]
            
        super().__init__(master, **kwargs)
        
        # Hover effect
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        
    def _on_enter(self, e):
        self["bg"] = COLORS["secondary"]
        
    def _on_leave(self, e):
        self["bg"] = COLORS["primary"] if self["fg"] == COLORS["text_light"] else "#EEEEEE"

def create_custom_dialog(root, title, width=500, height=400):
    """Create a modern custom dialog window"""
    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.geometry(f"{width}x{height}")
    dialog.configure(bg=COLORS["background"])
    dialog.transient(root)
    dialog.grab_set()
    
    # Center the dialog
    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() // 2) - (width // 2)
    y = (dialog.winfo_screenheight() // 2) - (height // 2)
    dialog.geometry(f"{width}x{height}+{x}+{y}")
    
    # Create main content frame
    content = create_card_frame(dialog)
    
    return dialog, content

class ModernEntry(tk.Frame):
    """Custom entry field with modern styling"""
    def __init__(self, master=None, show=None, width=20, placeholder="", **kwargs):
        super().__init__(master, bg=COLORS["card"], **kwargs)
        
        self.placeholder = placeholder
        self.placeholder_color = "#999999"
        self.default_fg_color = COLORS["text_dark"]
        
        # Create border frame for the nice outline
        self.border_frame = tk.Frame(self, bg=COLORS["primary"], padx=1, pady=1)
        self.border_frame.pack(fill="x")
        
        # Create the entry widget
        self.entry = tk.Entry(self.border_frame, width=width, show=show, font=("Segoe UI", 10),
                            bd=0, relief=tk.FLAT, insertbackground=COLORS["primary"])
        self.entry.pack(fill="x", ipady=8, padx=2, pady=2)
        
        # Set placeholder if provided
        if placeholder:
            self.entry.insert(0, placeholder)
            self.entry.config(fg=self.placeholder_color)
            
            # Bind events for placeholder behavior
            self.entry.bind("<FocusIn>", self._on_focus_in)
            self.entry.bind("<FocusOut>", self._on_focus_out)
    
    def _on_focus_in(self, event):
        if self.entry.get() == self.placeholder:
            self.entry.delete(0, tk.END)
            self.entry.config(fg=self.default_fg_color)
            # If this is a password field, apply the show character
            if self.entry.cget('show'):
                self.entry.config(show=self.entry.cget('show'))
    
    def _on_focus_out(self, event):
        if not self.entry.get():
            self.entry.insert(0, self.placeholder)
            self.entry.config(fg=self.placeholder_color)
            # If this is a password field, temporarily show the placeholder
            if self.entry.cget('show'):
                self.entry.config(show='')
    
    def get(self):
        """Get the entry value, returning empty string if it's just the placeholder"""
        value = self.entry.get()
        if value == self.placeholder:
            return ""
        return value
    
    def set(self, value):
        """Set the entry value, handling placeholder display"""
        current = self.entry.get()
        if current == self.placeholder:
            self.entry.delete(0, tk.END)
        
        self.entry.delete(0, tk.END)
        self.entry.insert(0, value)
        
        if not value and not self.entry.focus_get():
            self.entry.insert(0, self.placeholder)
            self.entry.config(fg=self.placeholder_color)
            if self.entry.cget('show'):
                self.entry.config(show='')
        else:
            self.entry.config(fg=self.default_fg_color)

def show_notification(root, message, type="info", duration=3000):
    """Show a modern toast notification"""
    colors = {
        "info": COLORS["primary"],
        "success": COLORS["success"],
        "error": COLORS["error"],
        "warning": COLORS["warning"]
    }
    
    # Create notification window
    notify = tk.Toplevel(root)
    notify.withdraw()  # Hide initially for animation
    notify.overrideredirect(True)  # Remove window decorations
    
    # Position at bottom right
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    width = 300
    height = 80
    x = screen_width - width - 20
    y = screen_height - height - 60
    
    # Frame with border
    frame = tk.Frame(notify, bg=colors[type], padx=2, pady=2)
    frame.pack(fill="both", expand=True)
    
    inner = tk.Frame(frame, bg=COLORS["card"], padx=15, pady=15)
    inner.pack(fill="both", expand=True)
    
    # Message
    tk.Label(inner, text=message, bg=COLORS["card"], 
           fg=COLORS["text_dark"], font=("Segoe UI", 10),
           wraplength=250, justify="left").pack(anchor="w")
    
    # Show with animation
    notify.geometry(f"{width}x{height}+{x}+{y}")
    notify.deiconify()
    
    # Fade in
    for i in range(10):
        notify.attributes("-alpha", i/10)
        notify.update()
        time.sleep(0.02)
    
    # Schedule removal
    def fade_out():
        for i in range(10, -1, -1):
            notify.attributes("-alpha", i/10)
            notify.update()
            time.sleep(0.02)
        notify.destroy()
    
    notify.after(duration, fade_out)

def create_password_strength_meter(parent, password_entry):
    """Create a visual password strength meter"""
    meter_frame = tk.Frame(parent, bg=COLORS["card"])
    meter_frame.pack(fill="x", pady=5)
    
    strength_label = tk.Label(meter_frame, text="Password Strength: ", 
                            bg=COLORS["card"], font=("Segoe UI", 9))
    strength_label.pack(side="left")
    
    meter = tk.Canvas(meter_frame, width=150, height=10, bg="#EEEEEE", 
                    highlightthickness=0)
    meter.pack(side="left", padx=5)
    
    strength_text = tk.Label(meter_frame, text="", bg=COLORS["card"], 
                           font=("Segoe UI", 9))
    strength_text.pack(side="left", padx=5)
    
    def update_meter(*args):
        password = password_entry.get()
        
        # Calculate strength (simplified)
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        criteria_met = sum([length >= 8, has_upper, has_lower, has_digit, has_special])
        
        # Set color and text based on strength
        if criteria_met == 0:
            color = "#EEEEEE"
            text = ""
            width = 0
        elif criteria_met <= 2:
            color = COLORS["error"]
            text = "Weak"
            width = 50
        elif criteria_met <= 4:
            color = COLORS["warning"]
            text = "Medium"
            width = 100
        else:
            color = COLORS["success"]
            text = "Strong"
            width = 150
        
        # Update meter
        meter.delete("all")
        meter.create_rectangle(0, 0, width, 10, fill=color, outline="")
        strength_text.config(text=text, fg=color)
    
    # Bind to password entry changes
    if hasattr(password_entry, 'entry'):
        # For our custom ModernEntry
        password_entry.entry.bind("<KeyRelease>", update_meter)
    else:
        # For standard tkinter Entry
        password_entry.bind("<KeyRelease>", update_meter)
    
    return meter_frame

# Function to create a sidebar menu item
def create_sidebar_item(parent, text, icon=None, command=None):
    """Create a styled sidebar menu item with optional icon"""
    btn_frame = tk.Frame(parent, bg=COLORS["primary"])
    btn_frame.pack(fill="x", pady=1)
    
    button = tk.Button(btn_frame, text=text, command=command,
                     bg=COLORS["primary"], fg=COLORS["text_light"],
                     relief=tk.FLAT, bd=0, font=("Segoe UI", 11),
                     activebackground=COLORS["secondary"],
                     activeforeground=COLORS["text_light"],
                     cursor="hand2", padx=10, pady=12, anchor="w",
                     width=18)
    
    if icon:
        # If we have an icon, place it to the left of the text
        button.configure(compound="left", image=icon, padx=5)
        button.image = icon  # Keep a reference
    
    button.pack(fill="x")
    
    # Hover effects
    button.bind("<Enter>", lambda e: button.configure(bg=COLORS["secondary"]))
    button.bind("<Leave>", lambda e: button.configure(bg=COLORS["primary"]))
    
    return btn_frame 