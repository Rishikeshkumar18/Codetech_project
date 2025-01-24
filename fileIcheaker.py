import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox

class FileIntegrityChecker:
    def __init__(self, master):
        self.master = master
        self.master.title("File Integrity Checker")
        self.master.configure(bg="black")

        self.file_hashes = {}

        # GUI Elements
        self.label = tk.Label(master, text="Select files to monitor:", bg="black", fg="lime", font=("Consolas", 12))
        self.label.pack(pady=10)

        self.add_button = tk.Button(master, text="Add File", command=self.add_file, bg="lime", fg="black", font=("Consolas", 10))
        self.add_button.pack(pady=5)

        self.files_listbox = tk.Listbox(master, width=50, height=10, bg="black", fg="lime", font=("Consolas", 10))
        self.files_listbox.pack(pady=10)

        self.check_button = tk.Button(master, text="Check Integrity", command=self.check_integrity, bg="lime", fg="black", font=("Consolas", 10))
        self.check_button.pack(pady=5)

        self.status_label = tk.Label(master, text="Status: Ready", bg="black", fg="lime", font=("Consolas", 12))
        self.status_label.pack(pady=10)

    def calculate_hash(self, filepath):
        """Calculate the SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as file:
                while chunk := file.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except FileNotFoundError:
            return None

    def add_file(self):
        """Add a file to monitor."""
        filepath = filedialog.askopenfilename()
        if filepath:
            file_hash = self.calculate_hash(filepath)
            if file_hash:
                self.file_hashes[filepath] = file_hash
                self.files_listbox.insert(tk.END, filepath)
                self.status_label.config(text="File added: " + os.path.basename(filepath), fg="lime")
            else:
                messagebox.showerror("Error", "Unable to read the file.")

    def check_integrity(self):
        """Check the integrity of monitored files."""
        changed_files = []
        for filepath, original_hash in self.file_hashes.items():
            current_hash = self.calculate_hash(filepath)
            if current_hash is None:
                changed_files.append((filepath, "File missing"))
            elif current_hash != original_hash:
                changed_files.append((filepath, "Modified"))

        if changed_files:
            message = "Changes detected:\n"
            for filepath, status in changed_files:
                message += f"{os.path.basename(filepath)} - {status}\n"
            messagebox.showwarning("Integrity Alert", message)
            self.status_label.config(text="Integrity check: Changes detected", fg="red")
        else:
            messagebox.showinfo("Integrity Check", "All files are intact.")
            self.status_label.config(text="Integrity check: All files are intact", fg="lime")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileIntegrityChecker(root)
    root.mainloop()
