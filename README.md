# Supabase SRP Challenge & E2EE 🔐

โปรเจกต์นี้เป็นการสาธิตการทำ **SRP Challenge (Secure Remote Password)** ร่วมกับ **End-to-End Encryption (E2EE)** และ **JWT Authentication** โดยใช้ Supabase เป็นฐานข้อมูลในการจัดเก็บ (Storage Layer)

จุดเด่นของสถาปัตยกรรมนี้คือ **"Zero-Knowledge Proof"** ทั้งฝั่ง Client และ Server สามารถเจรจา (Negotiate) เพื่อสร้าง "กุญแจเข้ารหัสลับ (Shared Session Key)" ที่เหมือนกันได้ โดยที่ **รหัสผ่านของ User จะไม่เคยถูกส่งผ่านอินเทอร์เน็ตเลย** 

กุญแจที่ได้จากการแลกเปลี่ยนนี้ จะถูกนำไปใช้ใน 2 ส่วน:
1. **Authentication**: Client ใช้กุญแจนี้เซ็น (Sign) JWT และ Server นำกุญแจเดียวกันมาเพื่อ Validate (แทนการใช้ Secret กลางตัวเดียว)
2. **Encryption (E2EE)**: Client ใช้กุญแจนี้เข้ารหัสข้อความ (AES-256-GCM) ก่อนบันทึกลงฐานข้อมูล ทำให้ Supabase ไม่สามารถอ่านข้อมูลดิบได้

---

## 🚨 Security Architecture & Risks (สำคัญมาก)

เพื่อให้ระบบมีความปลอดภัยสูงสุด **ห้ามให้ Client (Browser) ทำการดึงข้อมูล (Fetch) จาก Supabase โดยตรง** แต่ต้องใช้สถาปัตยกรรมแบบ **3-Tier** (Client ↔️ Node.js Server ↔️ Supabase)

### ความเสี่ยงหาก Client คุยกับ Supabase โดยตรง:
1. **Verifier Leak (Offline Dictionary Attack)**: ค่า `verifier` ในโปรโตคอล SRP มีสถานะเทียบเท่ากับ Password Hash หาก Client สามารถ Query ฐานข้อมูลโดยตรงได้ แฮกเกอร์จะสามารถดึง `verifier` ของผู้ใช้อื่นไปเพื่อสุ่มถอดรหัสผ่านแบบออฟไลน์ได้ ดังนั้น **Client จะต้องไม่มีสิทธิ์มองเห็น `verifier` เด็ดขาด**
2. **RLS (Row Level Security) Bypass**: ระบบนี้ใช้ Custom JWT ที่ Sign ด้วย Shared Session Key ซึ่ง Supabase ไม่รู้จัก JWT ตัวนี้ หาก Client พยายามดึงข้อมูล E2EE ข้อความด้วยตัวเอง จะไม่สามารถบังคับใช้ RLS เพื่อแยกแยะความเป็นเจ้าของข้อมูลได้ ทำให้เกิดความเสี่ยงที่ข้อมูลอาจถูกสแปมหรือถูกดึง Metadata ออกไป

### Best Practice Implementation:
* **Client (Browser)** ↔️ คุยผ่าน HTTP/REST API ↔️ **Node.js Server**
* **Node.js Server** ↔️ คุยผ่าน `supabase-js` ด้วย **Service Role Key** (Admin) ↔️ **Supabase**

---

## 🛠️ Tech Stack

- **Supabase SDK**: เป็น Backend Database สำหรับ Node.js Server
- **SRP-6a** (`secure-remote-password`): โปรโตคอลคณิตศาสตร์สำหรับการพิสูจน์รหัสผ่านแบบไม่ต้องส่งรหัส
- **Web Crypto API**: สำหรับฝั่ง Client (เบราว์เซอร์) ในการเข้ารหัส AES-GCM 
- **Jose / JSON Web Token**: ไลบรารีสำหรับสร้างและตรวจสอบ JWT 

---

## 🔄 Flow การทำงานเชิงปฏิบัติ (HTTP Request Sequence)

ในการนำไปเขียนเป็น API จริง การทำ SRP จะแบ่งเป็น **2 Steps (Pre-Auth และ Auth)** เพื่อลดการไป-กลับของ Network:

### 1. Registration Flow (ลงทะเบียน)
```mermaid
sequenceDiagram
    participant User
    participant Client (Browser)
    participant Server (Node.js)
    participant Supabase

    User->>Client (Browser): กรอก Username & Password
    Client (Browser)->>Client (Browser): สุ่ม `salt` (Salt)
    Client (Browser)->>Client (Browser): คำนวณ `privateKey` จาก Password + Salt
    Client (Browser)->>Client (Browser): สร้าง `verifier` จาก privateKey
    Client (Browser)->>Server (Node.js): [POST /register] { username, salt, verifier }
    Server (Node.js)->>Supabase: บันทึกลงตาราง srp_users
    Note over Client (Browser),Supabase: รหัสผ่านดิบไม่เคยถูกส่งออกไป
```

### 2. Login Flow (Pre-Auth & Auth)
```mermaid
sequenceDiagram
    participant Client (Browser)
    participant Server (Node.js)
    participant Supabase

    Note over Client (Browser),Server (Node.js): Step 1: Pre-Auth (Request Challenge)
    Client (Browser)->>Client (Browser): สร้าง Ephemeral Key A (Public & Secret)
    Client (Browser)->>Server (Node.js): [POST /login/challenge] { username, A }
    
    Server (Node.js)->>Supabase: ดึง `salt` และ `verifier` ด้วย username
    Supabase-->>Server (Node.js): คืนค่า `salt`, `verifier`
    Server (Node.js)->>Server (Node.js): สร้าง Ephemeral Key B จาก `verifier`
    Server (Node.js)-->>Client (Browser): ตอบกลับด้วย { salt, B }

    Note over Client (Browser),Server (Node.js): Step 2: Authenticate (Verify)
    Client (Browser)->>Client (Browser): คำนวณ Shared Session Key
    Client (Browser)->>Client (Browser): คำนวณ Client Proof (M1)
    Client (Browser)->>Server (Node.js): [POST /login/verify] { proof_M1 }

    Server (Node.js)->>Server (Node.js): คำนวณ Shared Session Key (ถ้าผิดจะพัง)
    Server (Node.js)->>Server (Node.js): Verify ค่า proof_M1 ของ Client
    Server (Node.js)->>Server (Node.js): นำ Shared Key มาเซ็น (Sign) JWT
    Server (Node.js)-->>Client (Browser): ตอบกลับด้วย { jwt_token }
    Note over Client (Browser),Server (Node.js): Authentication สำเร็จ!
```

### 3. End-to-End Encryption (E2EE)
```mermaid
sequenceDiagram
    participant Client (Browser)
    participant Server (Node.js)
    participant Supabase

    Note over Client (Browser): มีข้อความลับ "Hello World"
    Client (Browser)->>Client (Browser): เข้ารหัส (AES-256-GCM) ด้วย Shared Session Key
    Client (Browser)->>Server (Node.js): [POST /messages] { ciphertext, iv, jwt_token }
    
    Server (Node.js)->>Server (Node.js): Verify JWT ด้วย Shared Key ของ Server
    Server (Node.js)->>Supabase: บันทึก Ciphertext และ IV
    Note over Supabase: Server และ DB ไม่มีกุญแจในการถอดรหัส (E2EE)

    Client (Browser)->>Server (Node.js): [GET /messages] แนบ jwt_token
    Server (Node.js)->>Supabase: ดึงข้อมูลของ User
    Server (Node.js)-->>Client (Browser): คืนค่า { ciphertext, iv }
    Client (Browser)->>Client (Browser): นำ Shared Session Key มาถอดรหัสคืน
    Note over Client (Browser): ได้รับข้อความ "Hello World"
```

---

## 🚀 วิธีการทดสอบระบบ (How to run)

1. ติดตั้ง Dependencies ในโปรเจกต์
```bash
npm install
```

2. ตั้งค่า Environment Variables โดยคัดลอกจาก `.env.example`
```bash
cp .env.example .env
# จากนั้นแก้ไข .env ด้วย SUPABASE_URL และ SUPABASE_SERVICE_ROLE_KEY จริง
```

3. ทดลองรันโค้ดจำลองระบบ Client-Server (เพื่อดู Log การทำงานข้าม Environment)
```bash
npm run dev        # รัน server.ts (แนะนำ — แสดง flow แยก Client/Server)
# หรือ
npx tsx index.ts  # รัน index.ts (all-in-one demo รวม Supabase)
```

4. Build สำหรับ Production
```bash
npm run build   # compile TypeScript → dist/
npm start       # รัน compiled output
```
