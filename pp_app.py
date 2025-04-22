import streamlit as st
import sqlite3
from datetime import datetime, timedelta
import pandas as pd
import uuid
import os
from PIL import Image
import warnings
from streamlit_option_menu import option_menu
from passporteye import read_mrz
import pytesseract
from dateutil import parser
import json
import cv2
import matplotlib.image as mpimg
import easyocr
import string
import io
import hashlib
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from bidi.algorithm import get_display
import arabic_reshaper
# from arabic_reshaper import arabic

from reportlab.lib.units import inch, mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_RIGHT, TA_LEFT, TA_CENTER


# ---------- DATABASE SETUP ----------
conn = sqlite3.connect("passport_cases_2.db", check_same_thread=False)
c = conn.cursor()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_tables():
    # User table for authentication
    c.execute('''CREATE TABLE IF NOT EXISTS tbl_Users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'officer', 'viewer')),
            hash_password TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
    # c.execute("PRAGMA foreign_keys=OFF")  # Disable foreign key checks temporarily
    # c.execute("ALTER TABLE tbl_Users RENAME TO old_tbl_Users")

    # # Create new table with correct constraint
    # c.execute('''CREATE TABLE tbl_Users (
    #     user_id TEXT PRIMARY KEY,
    #     username TEXT UNIQUE NOT NULL,
    #     full_name TEXT NOT NULL,
    #     role TEXT NOT NULL CHECK(role IN ('admin', 'officer', 'viewer')),
    #     password_hash TEXT NOT NULL,
    #     is_active INTEGER DEFAULT 1,
    #     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    # )''')

    # # Copy data from old table
    # c.execute("INSERT INTO tbl_Users SELECT * FROM old_tbl_Users")
    # c.execute("DROP TABLE old_tbl_Users")
    # c.execute("PRAGMA foreign_keys=ON")

    
    # Session table for tracking active sessions
    c.execute('''CREATE TABLE IF NOT EXISTS tbl_Sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    login_time TEXT,
                    last_activity TEXT,
                    ip_address TEXT,
                    user_agent TEXT)''')

    # Existing tables
    c.execute('''CREATE TABLE IF NOT EXISTS tbl_Case (
                    case_id TEXT PRIMARY KEY,
                    case_type TEXT,
                    case_mode TEXT,
                    num_persons INTEGER,
                    created_date TEXT,
                    case_status TEXT,
                    processed_by TEXT)''')
    
    # c.execute('''ALTER TABLE tbl_Case ADD COLUMN report_printed INTEGER DEFAULT 0''')

    c.execute('''CREATE TABLE IF NOT EXISTS tbl_Passport (
                    passport_id TEXT PRIMARY KEY,
                    case_id TEXT,
                    surname TEXT,
                    name TEXT,
                    sex TEXT,
                    date_of_birth TEXT,
                    nationality TEXT,
                    passport_number TEXT,
                    issuing_country TEXT,
                    expiration_date TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS tbl_ApplicationDetails (
                    application_id TEXT PRIMARY KEY,
                    case_id TEXT,
                    apprif_no TEXT,
                    application_no TEXT,
                    total_fees REAL)''')

    c.execute('''CREATE TABLE IF NOT EXISTS tbl_ClientFees (
                    client_id TEXT PRIMARY KEY,
                    payment_mode TEXT,
                    bank_number TEXT,
                    total_payment_received REAL,              
                    case_id TEXT,
                    applicant_name TEXT,
                    contact_number TEXT,
                    other_expenses TEXT,
                    expense_amount REAL,
                    delivery_mode TEXT)''')

    # Create default admin user if not exists
    c.execute("SELECT COUNT(*) FROM tbl_Users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        password_hash = hash_password("admin123")
        c.execute("INSERT INTO tbl_Users (user_id, username, hash_password, full_name ,role, is_active) VALUES (?, ?, ?, ?, ?, ?)", 
                 (str(uuid.uuid4()), "admin", password_hash, "System Admin", "admin", 1))
    
    conn.commit()

create_tables()

# ---------- AUTHENTICATION HELPERS ----------


def verify_user(username, password):
    c.execute("SELECT user_id, hash_password, full_name, role FROM tbl_Users WHERE username = ? AND is_active = 1", 
              (username,))
    user = c.fetchone()
    if user and user[1] == hash_password(password):
        return {
            "user_id": user[0],
            "username": username,
            "full_name": user[2],
            "role": user[3]
        }
    return None

def create_session(user_id, ip="", user_agent=""):
    session_id = secrets.token_hex(16)
    now = datetime.now().isoformat()
    c.execute("INSERT INTO tbl_Sessions VALUES (?, ?, ?, ?, ?, ?)",
              (session_id, user_id, now, now, ip, user_agent))
    conn.commit()
    return session_id

def end_session(session_id):
    c.execute("DELETE FROM tbl_Sessions WHERE session_id = ?", (session_id,))
    conn.commit()

def validate_session(session_id):
    c.execute("SELECT user_id, last_activity FROM tbl_Sessions WHERE session_id = ?", 
              (session_id,))
    session = c.fetchone()
    if session:
        # Update last activity
        c.execute("UPDATE tbl_Sessions SET last_activity = ? WHERE session_id = ?",
                  (datetime.now().isoformat(), session_id))
        conn.commit()
        return session[0]  # Return user_id
    return None

def create_user(username, password, full_name, role):
    # Check if username exists
    c.execute("SELECT COUNT(*) FROM tbl_Users WHERE username = ?", (username,))
    if c.fetchone()[0] > 0:
        return False, "Username already exists"
    
    user_id = str(uuid.uuid4())
    password_hash = hash_password(password)
    c.execute("INSERT INTO tbl_Users VALUES (?, ?, ?, ?, ?, ?)",
              (user_id, username, password_hash, full_name, role, 1))
    conn.commit()
    return True, "User created successfully"

# ---------- SESSION STATE MANAGEMENT ----------
def init_session_state():
    if "auth" not in st.session_state:
        st.session_state.auth = {
            "logged_in": False,
            "user": None,
            "session_id": None
        }
    if "case" not in st.session_state:
        st.session_state.case = {
            "current_case": None,
            "edit_mode": False,
            "new_case": False
        }

init_session_state()





####### ---------- REPORT DEFINATION ----------#####



def arabic(text):
    return get_display(arabic_reshaper.reshape(text))


def calculate_column_widths(data, headers, arabic_headers, font_name='DejaVu', font_size=10):
    # Initialize column widths based on header lengths
    col_widths = [0] * len(headers)
    
    # Calculate widths for English headers
    for i, header in enumerate(headers):
        col_widths[i] = max(col_widths[i], len(header) * font_size * 0.6)  # Approximate width
    
    # Calculate widths for Arabic headers
    for i, header in enumerate(arabic_headers):
        col_widths[i] = max(col_widths[i], len(header) * font_size * 0.6)  # Arabic characters might be wider
    
    # Calculate widths for data rows
    for _, row in data.iterrows():
        for i, key in enumerate(["case_type", "apprif_no", "case_mode", "case_id", "total_fees", "total_payment_received"]):
            value = str(row.get(key, ""))
            col_widths[i] = max(col_widths[i], len(value) * font_size * 0.6)
    
    # Add some padding
    col_widths = [width + 20 for width in col_widths]
    
    # Set minimum and maximum widths
    min_width = 40
    max_width = 120
    col_widths = [max(min_width, min(width, max_width)) for width in col_widths]
    
    return col_widths
def generate_visa_report_pdf(filename, data):
    # Register fonts
    pdfmetrics.registerFont(TTFont("Arabic", "./ttf/NotoNaskhArabic-Regular.ttf"))
    pdfmetrics.registerFont(TTFont("DejaVu", "./ttf/DejaVuSansCondensed.ttf"))
    pdfmetrics.registerFont(TTFont("DejaVu-Bold", "./ttf/DejaVuSansCondensed-Bold.ttf"))

    # Create document
    doc = SimpleDocTemplate(filename, pagesize=A4, 
                          leftMargin=15*mm, rightMargin=15*mm,
                          topMargin=10*mm, bottomMargin=15*mm)
    elements = []
    
    # Custom styles
    styles = getSampleStyleSheet()
    
    # Title styles
    title_style_en = ParagraphStyle(
        name='TitleStyleEn', 
        fontName='DejaVu-Bold', 
        fontSize=18, 
        alignment=TA_CENTER,
        textColor=colors.HexColor("#2c3e50"),
        spaceAfter=4
    )
    
    title_style_ar = ParagraphStyle(
        name='TitleStyleAr', 
        fontName='Arabic', 
        fontSize=16, 
        alignment=TA_CENTER,
        textColor=colors.HexColor("#2c3e50"),
        spaceAfter=12
    )
    
    # Subtitle styles
    subtitle_style_en = ParagraphStyle(
        name='SubtitleStyleEn', 
        fontName='DejaVu-Bold', 
        fontSize=14, 
        alignment=TA_CENTER,
        textColor=colors.HexColor("#3498db"),
        spaceAfter=6
    )
    
    subtitle_style_ar = ParagraphStyle(
        name='SubtitleStyleAr', 
        fontName='Arabic', 
        fontSize=12, 
        alignment=TA_CENTER,
        textColor=colors.HexColor("#3498db"),
        spaceAfter=12
    )
    
    # Header styles
    header_style = ParagraphStyle(
        name='HeaderStyle',
        fontName='DejaVu-Bold',
        fontSize=10,
        textColor=colors.white,
        alignment=TA_CENTER
    )
    
    # Field name style
    field_style = ParagraphStyle(
        name='FieldStyle',
        fontName='DejaVu-Bold',
        fontSize=10,
        textColor=colors.HexColor("#2c3e50"),
        alignment=TA_LEFT
    )
    
    # Arabic label style
    arabic_label_style = ParagraphStyle(
        name='ArabicLabelStyle',
        fontName='Arabic',
        fontSize=10,
        textColor=colors.HexColor("#2c3e50"),
        alignment=TA_RIGHT
    )
    
    # Value style
    value_style = ParagraphStyle(
        name='ValueStyle',
        fontName='DejaVu',
        fontSize=10,
        textColor=colors.HexColor("#34495e"),
        alignment=TA_LEFT
    )
    
    # Metadata style
    meta_style = ParagraphStyle(
        name='MetaStyle',
        fontName='DejaVu',
        fontSize=9,
        textColor=colors.HexColor("#7f8c8d"),
        alignment=TA_LEFT,
        spaceAfter=12
    )
    
    # Add company header with logo placeholder
    elements.append(Paragraph("MRI Pvt. Ltd", title_style_en))
    elements.append(Paragraph(arabic("ام آر آئی پرائیویٹ لمیٹڈ"), title_style_ar))
    
    # Add decorative line
    elements.append(Spacer(1, 2))
    elements.append(Table(
        [[""]], 
        colWidths=[doc.width], 
        style=[('LINEABOVE', (0,0), (-1,-1), 1, colors.HexColor("#3498db"))]
    ))
    elements.append(Spacer(1, 8))
    
    # Add service title
    elements.append(Paragraph("Visa Services Facilitation for Saudia", subtitle_style_en))
    elements.append(Paragraph(arabic("سعودی عرب کے لیے ویزا سروسز کی سہولت"), subtitle_style_ar))
    elements.append(Spacer(1, 12))
    
    # Entry Date & Receipt
    created_date = data["created_date"].iloc[0]
    cashier = data["processed_by"].iloc[0]
    
    meta_table = Table([
        [Paragraph(f"<b>Entry Date:</b> {created_date}", meta_style), 
         Paragraph(f"<b>Cashier Receipt:</b> {cashier}", meta_style)]
    ], colWidths=[doc.width/2, doc.width/2])
    
    elements.append(meta_table)
    
    # Arabic labels mapping
    arabic_labels = {
        "Visa Centre": arabic("ویزا سینٹر"),
        "Apprif No.": arabic("اپریف نمبر"),
        "Visa Type": arabic("ویزا کی قسم"),
        "Case No.": arabic("کیس نمبر"),
        "Receipt by App": arabic("رسید درخواست دہندہ سے"),
        "Amount by Cash": arabic("نقدی میں رقم")
    }
    
    # Get the first row of data
    row = data.iloc[0]
    
    # Create vertical table data
    table_data = [
        [
            Paragraph("<b>Field</b>", header_style),
            Paragraph(arabic("<b>العنوان</b>"), header_style),
            Paragraph("<b>Value</b>", header_style)
        ]
    ]
    
    # Add data rows
    fields = [
        ("Visa Centre", "case_type"),
        ("Apprif No.", "apprif_no"),
        ("Visa Type", "case_mode"),
        ("Case No.", "case_id"),
        ("Receipt by App", "total_fees"),
        ("Amount by Cash", "total_payment_received")
    ]
    
    for field_name, data_key in fields:
        table_data.append([
            Paragraph(field_name, field_style),
            Paragraph(arabic_labels[field_name], arabic_label_style),
            Paragraph(str(row.get(data_key, "")), value_style)
        ])
    
    # Table styling
    table = Table(table_data, colWidths=[100, 120, doc.width-220])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#3498db")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('FONTNAME', (0,0), (0,-1), 'DejaVu-Bold'),
        ('FONTNAME', (1,0), (1,-1), 'Arabic'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('BOTTOMPADDING', (0,1), (-1,-1), 6),
        ('TOPPADDING', (0,1), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#ecf0f1")),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#bdc3c7")),
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 20))
    
    # Add footer
    footer_text = "Thank you for choosing our services. For any inquiries, please contact our support team."
    elements.append(Paragraph(footer_text, ParagraphStyle(
        name='FooterStyle',
        fontName='DejaVu',
        fontSize=9,
        textColor=colors.HexColor("#7f8c8d"),
        alignment=TA_CENTER
    )))
    
    # Add Arabic footer
    elements.append(Paragraph(arabic("خدماتنا اختيار لكم شكرا. أي استفسارات، يرجى الاتصال بفريق الدعم لدينا."), ParagraphStyle(
        name='FooterStyleAr',
        fontName='Arabic',
        fontSize=9,
        textColor=colors.HexColor("#7f8c8d"),
        alignment=TA_CENTER
    )))
    
    # Build the document
    doc.build(elements)

# ---------- USER INTERFACE COMPONENTS ----------
def login_form():
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.form_submit_button("Login"):
            user = verify_user(username, password)
            if user:
                session_id = create_session(user["user_id"])
                st.session_state.auth = {
                    "logged_in": True,
                    "user": user,
                    "session_id": session_id
                }
                st.rerun()
            else:
                st.error("Invalid username or password")

def logout_button():
    if st.button("Logout"):
        end_session(st.session_state.auth["session_id"])
        st.session_state.clear()
        init_session_state()
        st.rerun()

def user_management():
    if st.session_state.auth["user"]["role"] != "admin":
        st.warning("Only administrators can access this section")
        return
    
    st.subheader("User Management")
    
    tab1, tab2 = st.tabs(["Create User", "User List"])
    
    with tab1:
        with st.form("create_user_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            full_name = st.text_input("Full Name")
            role = st.selectbox("Role", ["admin", "agent"])
            
            if st.form_submit_button("Create User"):
                success, message = create_user(username, password, full_name, role)
                if success:
                    st.success(message)
                else:
                    st.error(message)
    
    with tab2:
        users = pd.read_sql_query("SELECT username, full_name, role, is_active FROM tbl_Users", conn)
        st.dataframe(users)


# ---------- HELPERS ----------
def generate_case_id():
    return f"CASE{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:5].upper()}"

def get_country_name(country_code):
    return country_code  # Simplified for this example

def get_sex(code):
    if code in ['M', 'm', 'F', 'f']:
        return code.upper()
    elif code == '0':
        return 'M'
    else:
        return 'F'

def parse_date(string, iob=True):
    try:
        date = parser.parse(string, yearfirst=True).date()
        return date.strftime('%Y-%m-%d')
    except parser.ParserError:
        print(f"Error parsing date: {string}")
        return None

def clean(string):
    return ''.join(i for i in string if i.isalnum()).upper()

def extract_passport_data(uploaded_file):
    temp_path = "temp_passport.jpg"
    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    user_info = {
        'surname': '',
        'name': '',
        'sex': '',
        'date_of_birth': '',
        'nationality': '',
        'passport_number': '',
        'issuing_country': '',
        'expiration_date': '',
    }
    
    try:
        mrz = read_mrz(temp_path, save_roi=True)
        
        if mrz:
            new_im_path = 'mrz_roi.png'
            mpimg.imsave(new_im_path, mrz.aux['roi'], cmap='gray')
            
            reader = easyocr.Reader(['en'])
            allowlist = string.ascii_letters + string.digits + '< '
            img = cv2.imread(new_im_path)
            img = cv2.resize(img, (1110, 140))
            code = reader.readtext(img, paragraph=False, detail=0, allowlist=allowlist)
            
            if len(code) >= 2:
                a, b = code[0].upper(), code[1].upper()
                
                if len(a) < 44:
                    a = a + '<' * (44 - len(a))
                if len(b) < 44:
                    b = b + '<' * (44 - len(b))
                
                surname_names = a[5:44].split('<<', 1)
                if len(surname_names) < 2:
                    surname_names += ['']
                surname, names = surname_names
                
                user_info['surname'] = surname.replace('<', ' ').strip().upper()
                user_info['name'] = names.replace('<', ' ').strip().upper()
                user_info['sex'] = get_sex(clean(b[20]))
                user_info['date_of_birth'] = parse_date(b[13:19])
                user_info['nationality'] = get_country_name(clean(b[10:13]))
                user_info['passport_number'] = clean(b[0:9])
                user_info['issuing_country'] = get_country_name(clean(a[2:5]))
                user_info['expiration_date'] = parse_date(b[21:27])
            
            if os.path.exists(new_im_path):
                os.remove(new_im_path)
    
    except Exception as e:
        st.error(f"Error processing passport image: {e}")
    
    if os.path.exists(temp_path):
        os.remove(temp_path)
    
    return user_info

def get_all_cases():
    df = pd.read_sql_query("SELECT * FROM tbl_Case ORDER BY created_date DESC", conn)
    return df

def get_case_details(case_id):
    c.execute("SELECT * FROM tbl_Case WHERE case_id = ?", (case_id,))
    return c.fetchone()

def update_case(case_data):
    c.execute('''UPDATE tbl_Case SET 
                case_type = ?,
                case_mode = ?,
                num_persons = ?,
                created_date = ?,
                case_status = ?,
                processed_by = ?
                WHERE case_id = ?''', 
              (case_data['case_type'], case_data['case_mode'], case_data['num_persons'],
               case_data['created_date'], case_data['case_status'], case_data['processed_by'],
               case_data['case_id']))
    conn.commit()

def get_passports_for_case(case_id):
    df = pd.read_sql_query("SELECT * FROM tbl_Passport WHERE case_id = ?", conn, params=(case_id,))
    return df
st.title('Passport Data Extraction & Management')

# Sidebar with login and navigation
with st.sidebar:
    if not st.session_state.auth["logged_in"]:
        login_form()
    else:
        user = st.session_state.auth["user"]
        st.success(f"Logged in as {user['full_name']} ({user['role']})")

        # Define menu options
        menu_options = ["Dashboard", "Step 1: Case Details", "Step 2: Passport Extraction", 
                        "Step 3: Application Info", "Step 4: Client Fees"]
        
        menu_options.append("Case Receipt")

        if user["role"] == "admin":
            menu_options.append("User Management")
        
        menu_options.append("Logout")

        # Display option menu
        selected = option_menu(
            menu_title="Main Menu",
            options=menu_options,
            icons=["grid", "clipboard", "camera", "file-earmark", "cash", "people", "box-arrow-right"],
            menu_icon="cast",
            default_index=menu_options.index(st.session_state.get("selected_page", "Step 1: Case Details")),
        )

        # Handle Logout
        if selected == "Logout":
            logout_button()
            st.stop()

# Main content
if st.session_state.auth["logged_in"]:
    # Navigation logic
    if selected == "Dashboard":
        st.subheader("📈 Dashboard Overview")
        df = pd.read_sql_query('''
        SELECT 
            cf.client_id, 
            cf.case_id, 
            c.case_status AS status, 
            cf.applicant_name, 
            cf.contact_number, 
            cf.total_payment_received, 
            cf.expense_amount, 
            cf.other_expenses, 
            cf.delivery_mode,
            ad.apprif_no,
            ad.total_fees,
            p.first_passport_name,
            p.first_passport_number
        FROM tbl_ClientFees cf
        JOIN tbl_Case c ON cf.case_id = c.case_id
        LEFT JOIN tbl_ApplicationDetails ad ON cf.case_id = ad.case_id
        LEFT JOIN (
            SELECT pp.case_id, 
                pp.name || ' ' || pp.surname AS first_passport_name,
                pp.passport_number AS first_passport_number
            FROM tbl_Passport pp
            INNER JOIN (
                SELECT case_id, MIN(passport_id) AS min_passport_id
                FROM tbl_Passport
                GROUP BY case_id
            ) grouped_pp ON pp.passport_id = grouped_pp.min_passport_id
        ) p ON cf.case_id = p.case_id
    ''', conn)


        if df.empty:
            st.info("No records found.")
            st.stop()

        APPLICATION_FEE = 5000  # fixed fee

        df["application_fee"] = APPLICATION_FEE
        df["net_total"] = df["total_payment_received"] - (df["application_fee"] + df["expense_amount"])

        col1, col2, col3 = st.columns(3)
        col1.metric("💼 Total Cases", len(df))
        col2.metric("💵 Total Received", f"Rs {df['total_payment_received'].sum():,.0f}")
        col3.metric("📉 Total Expenses", f"Rs {(df['application_fee'].sum() + df['expense_amount'].sum()):,.0f}")

        col4, col5 = st.columns(2)
        col4.metric("✅ Completed", df[df['status'].str.lower() == 'completed'].shape[0])
        col5.metric("🔄 In Process", df[df['status'].str.lower() == 'processed'].shape[0])

        st.subheader("📊 Case Status Distribution")
        status_counts = df['status'].value_counts()
        st.bar_chart(status_counts)

        

        export_df = df[[
            "case_id", "first_passport_name", "first_passport_number", "apprif_no",
            "applicant_name", "contact_number", "status",
            "total_payment_received", "application_fee", "expense_amount", "net_total"
        ]].rename(columns={
            "case_id": "Case Number",
            "first_passport_name": "Head Contact Name",
            "first_passport_number": "Head Passport Number",
            "apprif_no": "Apprif #",
            "applicant_name": "Applicant Name",
            "contact_number": "Applicant Contact Number",
            "status": "Status",
            "total_payment_received": "Total Payment Received",
            "application_fee": "Application Fee",
            "expense_amount": "Total Expense",
            "net_total": "Net Total"
        })

        st.subheader("📄 Case-wise Financial Summary")        
        st.dataframe(export_df, use_container_width=True)

        buffer = io.BytesIO()
        with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
            export_df.to_excel(writer, index=False, sheet_name='ClientFeesSummary')
            workbook = writer.book
            worksheet = writer.sheets['ClientFeesSummary']

            # Define formats
            header_format = workbook.add_format({
                'bold': True,
                'font_name': 'Arial',
                'font_size': 14,
                'border': 1,
                'align': 'center',
                'valign': 'vcenter',
                'bg_color': '#D9E1F2'
            })
            cell_format = workbook.add_format({
                'font_name': 'Arial',
                'font_size': 14,
                'border': 1
            })

            # Apply header format
            for col_num, value in enumerate(export_df.columns.values):
                worksheet.write(0, col_num, value, header_format)

            # Apply cell format
            for row_num in range(1, len(export_df) + 1):
                for col_num in range(len(export_df.columns)):
                    worksheet.write(row_num, col_num, export_df.iloc[row_num - 1, col_num], cell_format)

            # Optional: Autofit columns
            for i, column in enumerate(export_df.columns):
                column_width = max(export_df[column].astype(str).map(len).max(), len(column)) + 2
                worksheet.set_column(i, i, column_width)

        # Streamlit download button
        st.download_button(
            label="📥 Download Excel",
            data=buffer,
            file_name=f"Client_Fees_Summary_{datetime.now().date()}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

        # st.download_button(
        #     label="📥 Download Excel",
        #     data=buffer,
        #     file_name=f"Client_Fees_Summary_{datetime.now().date()}.xlsx",
        #     mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        # )

    
    # STEP 1: Case Details
    elif selected == "Step 1: Case Details":
        st.subheader("📝 Step 1: Case Details")
        
        # In the case form, modify the processed_by field to be auto-filled and disabled:
        # with st.form("case_form"):
        #     if st.session_state.case.get("current_case"):
        #         case_id = st.text_input("Case Number", value=st.session_state.current_case['case_id'], disabled=True)
        #         edit_mode = True
        #     else:
        #         case_id = generate_case_id()
        #         st.text_input("Case Number", value=case_id, disabled=True)
        #         edit_mode = False
            
        #     # ... other form fields ...
            
        #     # Auto-filled and disabled processed_by field
        #     processed_by = st.text_input("Processed By", 
        #                                 value=user['full_name'], 
        #                                 disabled=True)
        
        # if choice == menu[1]:
        #     st.subheader("📝 Step 1: Case Details")

        # Load all cases
        cases_df = get_all_cases()
        selected_case = None

        # Display cases if available
        if not cases_df.empty:
            st.write("### Existing Cases")

            # Dropdown to select a case
            selected_case = st.selectbox("Select a case to edit:", cases_df['case_id'], key="case_select")

            # Load selected case data if not in new case mode
            if "new_case" not in st.session_state or not st.session_state.new_case:
                if selected_case:
                    case_data = get_case_details(selected_case)
                    if case_data:
                        st.session_state.current_case = {
                            'case_id': case_data[0],
                            'case_type': case_data[1],
                            'case_mode': case_data[2],
                            'num_persons': case_data[3],
                            'created_date': case_data[4],
                            'case_status': case_data[5],
                            'processed_by': case_data[6]
                        }
                        st.session_state.edit_mode = True

        # Button to create new case
        if st.button("Create New Case"):
            st.session_state.current_case = None
            st.session_state.edit_mode = False
            st.session_state.new_case = True
            st.session_state.generated_case_id = generate_case_id()  # <-- Store case ID here
            st.rerun()

        # Form starts here
        with st.form("case_form"):
           


            if st.session_state.get("current_case"):
                case_id = st.text_input("Case Number", value=st.session_state.current_case['case_id'], disabled=True)
                edit_mode = True
            else:
                if "generated_case_id" not in st.session_state:
                    st.session_state.generated_case_id = generate_case_id()
                case_id = st.text_input("Case Number", value=st.session_state.generated_case_id, disabled=True)
                edit_mode = False
            
            
            
            # Auto-filled and disabled processed_by field
            processed_by = st.text_input("Processed By", 
                                        value=user['full_name'], 
                                        disabled=True)
        

            case_type = st.selectbox("Visa Category", ["Family Visit", "Business", "Other"],
                                    index=["Family Visit", "Business", "Other"].index(
                                        st.session_state.current_case['case_type']) if st.session_state.get("current_case") else 0)

            case_mode = st.selectbox("Visa Type", ["Single", "Multiple"],
                                    index=["Single", "Multiple"].index(
                                        st.session_state.current_case['case_mode']) if st.session_state.get("current_case") else 0)

            num_persons = st.slider("Number of Persons", 1, 7,
                                    value=st.session_state.current_case['num_persons'] if st.session_state.get("current_case") else 1)

            created_date = st.date_input("Case Created Date",
                                        value=parser.parse(st.session_state.current_case['created_date']).date()
                                        if st.session_state.get("current_case") else datetime.now())

            case_status = st.selectbox("Case Status", ["Need to process", "In process", "Completed"],
                                    index=["Need to process", "In process", "Completed"].index(
                                        st.session_state.current_case['case_status']) if st.session_state.get("current_case") else 0)

            # processed_by = st.text_input("Processed By",
            #                             value=st.session_state.current_case['processed_by']
            #                             if st.session_state.get("current_case") else "")

            col1, col2, col3 = st.columns(3)
        
            with col1:
                submitted = st.form_submit_button("Save Case")
            
            with col2:
                if st.form_submit_button("Clear Form"):
                    st.session_state.current_case = None
                    st.session_state.new_case = True
                    st.rerun()
            
            with col3:
                if st.form_submit_button("Next Step ➡️"):
                    current_index = menu_options.index(selected)
                    next_index = (current_index + 1) % len(menu_options)
                    
                    # Skip Logout in next step logic
                    while menu_options[next_index] == "Logout":
                        next_index = (next_index + 1) % len(menu_options)
                    
                    # Set the next selected menu
                    st.session_state.selected_page = menu_options[next_index]
                    st.rerun()

            if submitted:
                case_data = {
                    'case_id': case_id,
                    'case_type': case_type,
                    'case_mode': case_mode,
                    'num_persons': num_persons,
                    'created_date': created_date.strftime('%Y-%m-%d'),
                    'case_status': case_status,
                    'processed_by': processed_by
                }

                if edit_mode:
                    update_case(case_data)
                    st.success("Case updated successfully!")
                else:
                    c.execute("INSERT INTO tbl_Case VALUES (?, ?, ?, ?, ?, ?, ?,?)",
                            (case_id, case_type, case_mode, num_persons,
                            created_date.strftime('%Y-%m-%d'), case_status, processed_by,0))
                    conn.commit()
                    st.success(f"Case saved with ID: {case_id}")
                
                previous_status = st.session_state.current_case['case_status'] if edit_mode else None
                new_status = case_status

                if previous_status != new_status and new_status == "Completed":
                    import shutil

                    old_folder = os.path.join("passport_images", previous_status, case_id)
                    new_folder = os.path.join("passport_images", "Completed", case_id)

                    if os.path.exists(old_folder):
                        os.makedirs(new_folder, exist_ok=True)
                        for file in os.listdir(old_folder):
                            shutil.move(os.path.join(old_folder, file), os.path.join(new_folder, file))
                        shutil.rmtree(old_folder, ignore_errors=True)

                # Reset session and rerun
                st.session_state.current_case = case_data
                st.session_state.edit_mode = True
                st.session_state.new_case = False
                st.rerun()



    # STEP 2: Passport Extraction (Simplified)
    elif selected == "Step 2: Passport Extraction":
        st.subheader("🛂 Step 2: Passport Data Extraction")
        
        # Initialize session state variables if they don't exist
        if 'passport_saved' not in st.session_state:
            st.session_state.passport_saved = False
        if 'show_passport_form' not in st.session_state:
            st.session_state.show_passport_form = True
        
        # Get all cases for selection
        cases_df = get_all_cases()
        if cases_df.empty:
            st.warning("No cases found. Please create a case first.")
            st.stop()
        
        case_id = st.selectbox("Select Case ID", cases_df['case_id'])
        
        # Get current case details
        case_details = get_case_details(case_id)
        case_mode = case_details[2]  # Case mode (Single/Multiple)
        number_of_persons = int(case_details[3])  # Number of persons
        case_status = case_details[5]  # Case status

        # Show existing passports for this case
        passports_df = get_passports_for_case(case_id)
        existing_passport_count = len(passports_df)

        if not passports_df.empty:
            st.write("### Existing Passports for this Case")
            st.dataframe(passports_df.drop(columns=['passport_id', 'case_id']))

        # Validate passport count
        if str(case_mode).lower() == 'multiple':
            if existing_passport_count >= number_of_persons:
                st.warning(f"Expected {number_of_persons} passports. You've already added {existing_passport_count}.")
                st.stop()
        elif str(case_mode).lower() == 'single' and existing_passport_count >= 1:
            st.warning("Only one passport is allowed in Single mode.")
            st.stop()

        # Main container that will always show navigation buttons
        with st.container():
            if not st.session_state.passport_saved:
                # Show upload form only if passport not saved yet
                uploaded_file = st.file_uploader("Upload Passport Image", type=["jpg", "jpeg", "png"])
                
                if uploaded_file:
                    st.image(uploaded_file, caption="Uploaded Passport", use_column_width=True)
                    
                    # Extract passport data
                    data = extract_passport_data(uploaded_file)
                    
                    if data:
                        st.info("Check and correct extracted data if necessary")
                        with st.form("passport_form"):
                            data['surname'] = st.text_input("Surname", value=data['surname'])
                            data['name'] = st.text_input("Name", value=data['name'])
                            data['sex'] = st.text_input("Sex", value=data['sex'])
                            data['date_of_birth'] = st.text_input("Date of Birth", value=data['date_of_birth'])
                            data['nationality'] = st.text_input("Nationality", value=data['nationality'])
                            data['passport_number'] = st.text_input("Passport Number", value=data['passport_number'])
                            data['issuing_country'] = st.text_input("Issuing Country", value=data['issuing_country'])
                            data['expiration_date'] = st.text_input("Expiration Date", value=data['expiration_date'])
                            
                            col1, col2, col3 = st.columns(3)
                            
                            with col1:
                                submitted = st.form_submit_button("Save Passport Data")
                            
                            with col2:
                                if st.form_submit_button("Clear Form"):
                                    st.session_state.show_passport_form = True
                                    st.rerun()
                            
                            if submitted:
                                passport_id = str(uuid.uuid4())

                                # Save uploaded image
                                folder = os.path.join("passport_images", case_status, case_id)
                                os.makedirs(folder, exist_ok=True)
                                image_path = os.path.join(folder, f"{passport_id}.jpg")
                                image = Image.open(uploaded_file)
                                image.save(image_path)

                                # Save to DB
                                try:
                                    c.execute('''INSERT INTO tbl_Passport (
                                        passport_id, case_id, surname, name, sex, date_of_birth, 
                                        nationality, passport_number, issuing_country, expiration_date
                                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                    (
                                        passport_id, case_id, data['surname'], data['name'], data['sex'], 
                                        data['date_of_birth'], data['nationality'], data['passport_number'],
                                        data['issuing_country'], data['expiration_date']
                                    ))
                                    conn.commit()
                                    st.session_state.passport_saved = True
                                    st.session_state.show_passport_form = False
                                    st.rerun()
                                except sqlite3.Error as e:
                                    st.error(f"Error saving passport data: {e}")
            else:
                st.success("✅ Passport data saved successfully!")
                st.write("You can now proceed to the next step or upload another passport if needed.")
                
                # Show the saved passport data
                latest_passport = get_passports_for_case(case_id).iloc[-1]
                st.write("### Saved Passport Details")
                st.json(latest_passport.to_dict())
                
                # Always show navigation buttons
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("Add Another Passport"):
                        st.session_state.passport_saved = False
                        st.session_state.show_passport_form = True
                        st.rerun()
                
                with col3:
                    if st.button("Next Step ➡️"):
                        current_index = menu_options.index(selected)
                        next_index = (current_index + 1) % len(menu_options)
                        
                        # Skip Logout in next step logic
                        while menu_options[next_index] == "Logout":
                            next_index = (next_index + 1) % len(menu_options)
                        
                        # Set the next selected menu
                        st.session_state.selected_page = menu_options[next_index]
                        st.session_state.passport_saved = False  # Reset for next time
                        st.rerun()


    # STEP 3: Application Info
    elif selected == "Step 3: Application Info":
        st.subheader("📌 Step 3: Application Information")
        
        # Get all cases for selection
        cases_df = get_all_cases()
        if cases_df.empty:
            st.warning("No cases found. Please create a case first.")
            st.stop()
        
        case_id = st.selectbox("Select Case ID", cases_df['case_id'])
        
        # Show existing application info
        c.execute("SELECT * FROM tbl_ApplicationDetails WHERE case_id = ?", (case_id,))
        app_data = c.fetchone()
        
        with st.form("app_form"):

        
            apprif_no = st.text_input("Apprif / Ref. No", value=app_data[2] if app_data else "")
            application_no = st.text_input("Application / E No", value=app_data[3] if app_data else "")
            total_fees = st.number_input("Total Fees", min_value=0.0, format="%.2f", 
                                        value=float(app_data[4]) if app_data else 0.0)
            
            col1, col2, col3 = st.columns(3)
    
            with col1:
                submitted = st.form_submit_button("Save Application Info")
            
            with col2:
                if st.form_submit_button("Clear Form"):
                    st.rerun()
            
            with col3:
                if st.form_submit_button("Next Step ➡️"):
                    current_index = menu_options.index(selected)
                    next_index = (current_index + 1) % len(menu_options)
                    
                    # Skip Logout in next step logic
                    while menu_options[next_index] == "Logout":
                        next_index = (next_index + 1) % len(menu_options)
                    
                    # Set the next selected menu
                    st.session_state.selected_page = menu_options[next_index]
                    st.rerun()
            
            if submitted:
                if app_data:
                    # Update existing record
                    c.execute('''UPDATE tbl_ApplicationDetails SET 
                                apprif_no = ?,
                                application_no = ?,
                                total_fees = ?
                                WHERE case_id = ?''',
                            (apprif_no, application_no, total_fees, case_id))
                else:
                    # Insert new record
                    application_id = str(uuid.uuid4())
                    c.execute("INSERT INTO tbl_ApplicationDetails VALUES (?, ?, ?, ?, ?)",
                            (application_id, case_id, apprif_no, application_no, total_fees))
                
                conn.commit()
                st.success("Application information saved!")

    elif selected == "Step 4: Client Fees":
        st.subheader("💵 Step 4: Client Fees")

        # Get all cases for selection
        cases_df = get_all_cases()
        if cases_df.empty:
            st.warning("No cases found. Please create a case first.")
            st.stop()

        case_id = st.selectbox("Select Case ID", cases_df['case_id'])

        # Show existing client fees info
        c.execute("SELECT * FROM tbl_ClientFees WHERE case_id = ?", (case_id,))
        fees_data = c.fetchone()

        with st.form("fees_form"):
            # -- Payment Mode --
            valid_payment_modes = ["Cash", "Bank"]
            payment_mode_value = fees_data[1] if fees_data and fees_data[1] in valid_payment_modes else "Cash"
            payment_mode = st.selectbox("Payment Received Mode", valid_payment_modes,
                                        index=valid_payment_modes.index(payment_mode_value))

            # -- Bank Number (optional) --
            bank_number = ""
            if payment_mode == "Bank":
                bank_number = st.text_input("Bank / Easypaisa Number", value=fees_data[2] if fees_data else "")

            # -- Total Received --
            try:
                total_payment_received = float(fees_data[3]) if fees_data else 0.0
            except (ValueError, TypeError):
                total_payment_received = 0.0

            total_received = st.number_input("Total Payment Received", min_value=0.0, format="%.2f",
                                            value=total_payment_received)

            # -- Other Details --
            applicant_name = st.text_input("Applicant Name", value=fees_data[5] if fees_data else "")
            contact_number = st.text_input("Contact Number", value=fees_data[6] if fees_data else "")
            other_expenses = st.text_area("Other Expenses", value=fees_data[7] if fees_data else "")

            try:
                expense_amount = float(fees_data[8]) if fees_data else 0.0
            except (ValueError, TypeError):
                expense_amount = 0.0

            expense_amount = st.number_input("Expense Amount", min_value=0.0, format="%.2f", value=expense_amount)

            valid_delivery_modes = ["By Hand", "By Post"]
            delivery_mode_value = fees_data[9] if fees_data and fees_data[9] in valid_delivery_modes else "By Hand"
            delivery_mode = st.selectbox("Delivery Mode", valid_delivery_modes,
                                        index=valid_delivery_modes.index(delivery_mode_value))

            # ✅ Submit
            col1, col2 = st.columns(2)
        
            with col1:
                submitted = st.form_submit_button("Save Client Fees")
            
            with col2:
                if st.form_submit_button("Clear Form"):
                    st.rerun()
            
            # with col3:
            #     if st.form_submit_button("Next Step ➡️"):
            #         current_index = menu_options.index(selected)
            #         next_index = (current_index + 1) % len(menu_options)
                    
            #         # Skip Logout in next step logic
            #         while menu_options[next_index] == "Logout":
            #             next_index = (next_index + 1) % len(menu_options)
                    
            #         # Set the next selected menu
            #         st.session_state.selected_page = menu_options[next_index]
            #         st.rerun()

            if submitted:
                if fees_data:
                    # -- UPDATE Existing Record --
                    c.execute('''UPDATE tbl_ClientFees SET 
                                payment_mode = ?,
                                bank_number = ?,
                                total_payment_received = ?,
                                applicant_name = ?,
                                contact_number = ?,
                                other_expenses = ?,
                                expense_amount = ?,
                                delivery_mode = ?
                                WHERE case_id = ?''',
                            (payment_mode, bank_number, total_received,
                            applicant_name, contact_number, other_expenses,
                            expense_amount, delivery_mode, case_id))
                else:
                    # -- INSERT New Record --
                    client_id = str(uuid.uuid4())
                    c.execute('''INSERT INTO tbl_ClientFees (
                                client_id, payment_mode, bank_number, total_payment_received,
                                case_id, applicant_name, contact_number, other_expenses,
                                expense_amount, delivery_mode
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (client_id, payment_mode, bank_number, total_received,
                            case_id, applicant_name, contact_number, other_expenses,
                            expense_amount, delivery_mode))

                conn.commit()
                st.success("Client fees data saved successfully!")
    elif selected == "User Management":
        
        st.subheader("👥 User Management")
        
        # Check if current user is admin
        if user['role'] != 'admin':
            st.warning("⛔ Only administrators can access this section")
            st.stop()
        
        # Initialize session state for user management
        if 'user_management_mode' not in st.session_state:
            st.session_state.user_management_mode = "view"  # view, create, edit
        
        if 'selected_user_id' not in st.session_state:
            st.session_state.selected_user_id = None
        
        # Available roles
        # Change this line in your User Management section
        AVAILABLE_ROLES = ["admin", "officer", "viewer"]  # Make sure this matches your CHECK constraint
        
        # Display mode selection
        mode_col1, mode_col2, mode_col3 = st.columns(3)
        with mode_col1:
            if st.button("View All Users"):
                st.session_state.user_management_mode = "view"
                st.rerun()
        with mode_col2:
            if st.button("Create New User"):
                st.session_state.user_management_mode = "create"
                st.rerun()
        
        # View all users mode
        if st.session_state.user_management_mode == "view":
            st.write("### All Users")
            
            # Get all users from database
            c.execute("SELECT user_id, username, full_name, role, is_active FROM tbl_Users")
            users = c.fetchall()
            
            if not users:
                st.info("No users found in the system")
            else:
                # Display users in a table with actions
                for idx, (user_id, username, full_name, role, is_active) in enumerate(users):
                    cols = st.columns([2, 2, 2, 1, 1, 1])
                    with cols[0]:
                        st.write(f"**{username}**")
                    with cols[1]:
                        st.write(full_name)
                    with cols[2]:
                        st.write(f"`{role}`")
                    with cols[3]:
                        status = "🟢 Active" if is_active else "🔴 Inactive"
                        st.write(status)
                    with cols[4]:
                        if st.button("Edit", key=f"edit_{user_id}"):
                            st.session_state.user_management_mode = "edit"
                            st.session_state.selected_user_id = user_id
                            st.rerun()
                    with cols[5]:
                        if st.button("Delete", key=f"del_{user_id}"):
                            c.execute("UPDATE tbl_Users SET is_active = 0 WHERE user_id = ?", (user_id,))
                            conn.commit()
                            st.success(f"User {username} deactivated successfully!")
                            st.rerun()
        
        # Create new user mode
        elif st.session_state.user_management_mode == "create":
            st.write("### Create New User")
            
            with st.form("create_user_form"):
                username = st.text_input("Username (must be unique)")
                full_name = st.text_input("Full Name")
                role = st.selectbox("Role", AVAILABLE_ROLES)
                password = st.text_input("Password", type="password")
                confirm_password = st.text_input("Confirm Password", type="password")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.form_submit_button("Create User"):
                        # Validate inputs
                        if not username or not full_name or not password:
                            st.error("Please fill all required fields")
                        elif password != confirm_password:
                            st.error("Passwords do not match")
                        else:
                            # Check if username exists
                            c.execute("SELECT username FROM tbl_Users WHERE username = ?", (username,))
                            if c.fetchone():
                                st.error("Username already exists")
                            else:
                                # Hash password
                                hashed_password = generate_password_hash(password)
                                
                                # Insert new user
                                c.execute(
                                    "INSERT INTO tbl_Users (username, full_name, role, hash_password, is_active) VALUES (?, ?, ?, ?, 1)",
                                    (username, full_name, role, hashed_password)
                                )
                                conn.commit()
                                st.success(f"User {username} created successfully!")
                                st.session_state.user_management_mode = "view"
                                st.rerun()
                with col2:
                    if st.form_submit_button("Cancel"):
                        st.session_state.user_management_mode = "view"
                        st.rerun()
        
        # Edit user mode
        elif st.session_state.user_management_mode == "edit":
            st.write("### Edit User")
            
            # Get user details
            c.execute(
                "SELECT username, full_name, role, is_active FROM tbl_Users WHERE user_id = ?",
                (st.session_state.selected_user_id,)
            )
            user_data = c.fetchone()
            
            if not user_data:
                st.error("User not found")
                st.session_state.user_management_mode = "view"
                st.rerun()
            
            username, full_name, role, is_active = user_data
            
            with st.form("edit_user_form"):
                st.write(f"**Username:** {username}")  # Username shouldn't be changed
                new_full_name = st.text_input("Full Name", value=full_name)
                new_role = st.selectbox("Role", AVAILABLE_ROLES, index=AVAILABLE_ROLES.index(role))
                new_password = st.text_input("New Password (leave blank to keep current)", type="password")
                confirm_password = st.text_input("Confirm New Password", type="password")
                user_status = st.radio("Account Status", ["Active", "Inactive"], index=0 if is_active else 1)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    if st.form_submit_button("Save Changes"):
                        # Prepare update data
                        update_data = {
                            'full_name': new_full_name,
                            'role': new_role,
                            'is_active': 1 if user_status == "Active" else 0
                        }
                        
                        # Only update password if provided
                        if new_password:
                            if new_password != confirm_password:
                                st.error("Passwords do not match")
                            else:
                                update_data['hash_password'] = generate_password_hash(new_password)
                        
                        # Execute update
                        set_clause = ", ".join([f"{k} = ?" for k in update_data])
                        values = list(update_data.values()) + [st.session_state.selected_user_id]
                        
                        c.execute(
                            f"UPDATE tbl_Users SET {set_clause} WHERE user_id = ?",
                            values
                        )
                        conn.commit()
                        st.success("User updated successfully!")
                        st.session_state.user_management_mode = "view"
                        st.rerun()
                
                with col2:
                    if st.form_submit_button("Reset Password"):
                        # Generate a random password
                        import random
                        import string
                        temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                        
                        # Update password
                        c.execute(
                            "UPDATE tbl_Users SET hash_password = ? WHERE user_id = ?",
                            (generate_password_hash(temp_password), st.session_state.selected_user_id)
                        )
                        conn.commit()
                        st.success(f"Password reset successfully! Temporary password: {temp_password}")
                
                with col3:
                    if st.form_submit_button("Cancel"):
                        st.session_state.user_management_mode = "view"
                        st.rerun()

    elif selected == "Case Receipt":
        st.subheader("👥 Case Receipt")
        search_type = st.selectbox("Search by", ["Passport Number", "Application Number", "Apprif Number"])

        # Fetch options based on selected type
        dropdown_options = []
        if search_type == "Passport Number":
            dropdown_options = [row[0] for row in c.execute("""
                SELECT DISTINCT pp.passport_number 
                FROM tbl_Passport pp
                JOIN tbl_Case ca ON ca.case_id = pp.case_id 
                WHERE ca.report_printed = 0 AND pp.passport_number IS NOT NULL
            """).fetchall()]
        elif search_type == "Application Number":
            dropdown_options = [row[0] for row in c.execute("""
                SELECT DISTINCT ad.application_no 
                FROM tbl_ApplicationDetails ad
                JOIN tbl_Case ca ON ca.case_id = ad.case_id
                WHERE ca.report_printed = 0 AND ad.application_no IS NOT NULL
            """).fetchall()]
        elif search_type == "Apprif Number":
            dropdown_options = [row[0] for row in c.execute("""
                SELECT DISTINCT ad.apprif_no 
                FROM tbl_ApplicationDetails ad
                JOIN tbl_Case ca ON ca.case_id = ad.case_id
                WHERE ca.report_printed = 0 AND ad.apprif_no IS NOT NULL
            """).fetchall()]

        search_value = st.selectbox(f"Select {search_type}", dropdown_options) if dropdown_options else None

        if "search_result" not in st.session_state:
            st.session_state.search_result = pd.DataFrame()

        if search_value and st.button("Search"):
            query = ""
            if search_type == "Passport Number":
                query = """SELECT ca.*, pp.passport_number, ad.apprif_no, ad.application_no, ad.total_fees, 
                                cf.total_payment_received, cf.payment_mode, cf.bank_number
                        FROM tbl_Case ca
                        LEFT JOIN tbl_Passport pp ON ca.case_id = pp.case_id
                        LEFT JOIN tbl_ApplicationDetails ad ON ca.case_id = ad.case_id
                        LEFT JOIN tbl_ClientFees cf ON ca.case_id = cf.case_id
                        WHERE pp.passport_number = ?"""
            elif search_type == "Application Number":
                query = """SELECT ca.*, pp.passport_number, ad.apprif_no, ad.application_no, ad.total_fees, 
                                cf.total_payment_received, cf.payment_mode, cf.bank_number
                        FROM tbl_Case ca
                        LEFT JOIN tbl_Passport pp ON ca.case_id = pp.case_id
                        LEFT JOIN tbl_ApplicationDetails ad ON ca.case_id = ad.case_id
                        LEFT JOIN tbl_ClientFees cf ON ca.case_id = cf.case_id
                        WHERE ad.application_no = ?"""
            elif search_type == "Apprif Number":
                query = """SELECT ca.*, pp.passport_number, ad.apprif_no, ad.application_no, ad.total_fees, 
                                cf.total_payment_received, cf.payment_mode, cf.bank_number
                        FROM tbl_Case ca
                        LEFT JOIN tbl_Passport pp ON ca.case_id = pp.case_id
                        LEFT JOIN tbl_ApplicationDetails ad ON ca.case_id = ad.case_id
                        LEFT JOIN tbl_ClientFees cf ON ca.case_id = cf.case_id
                        WHERE ad.apprif_no = ?"""

            result = pd.read_sql_query(query, conn, params=(search_value,))
            st.session_state.search_result = result

        result = st.session_state.search_result

        if not result.empty:
            case_id = result["case_id"].iloc[0]
            printed = c.execute("SELECT report_printed FROM tbl_Case WHERE case_id = ?", (case_id,)).fetchone()[0]
            if printed:
                st.warning("⚠️ This report has already been printed and cannot be reprinted.")
            else:
                st.dataframe(result)

                if st.button("🖨️ Print Report", key="print_btn"):
                    filename = f"Visa_Report_{case_id}.pdf"
                    generate_visa_report_pdf(filename, result)
                    c.execute("UPDATE tbl_Case SET report_printed = 1 WHERE case_id = ?", (case_id,))
                    conn.commit()
                    with open(filename, "rb") as f:
                        st.download_button("Download Report", data=f, file_name=filename, mime="application/pdf")
        elif search_value:
            st.error("No records found.")



