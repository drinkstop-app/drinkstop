require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'nasz_tajny_klucz_123';

// --- MIDDLEWARE DO WERYFIKACJI JWT ---
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ message: 'Brak tokenu autoryzacyjnego. Zaloguj się ponownie.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Nieprawidłowy lub wygasły token.' });
        }
        req.user = user; // { id: ... }
        next();
    });
};

// --- 1. POŁĄCZENIE Z BAZĄ DANYCH ---
const dbLink = process.env.MONGO_URI;

mongoose.connect(dbLink)
    .then(() => console.log('✅ Udało się! Połączono z bazą MongoDB Drink Stop.'))
    .catch((err) => console.error('❌ Błąd połączenia z bazą danych:', err));

// --- 2. SCHEMAT UŻYTKOWNIKA ---
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    age: Number,
    city: String,
    password: String,
    isVerified: { type: Boolean, default: false }, 
    verificationToken: String,
    resetPasswordToken: String,        
    resetPasswordExpires: Date,
    status: { type: String, default: 'free' },
    interests: { type: String, default: '' },
    desc: { type: String, default: '' },
    photo: { type: String, default: '' },
    marketingConsent: { type: Boolean, default: false },
    deletionRequested: { type: Boolean, default: false },
    deletionDate: { type: Date, default: null },
    eventCredits: { type: Number, default: 0 }
});
const User = mongoose.model('User', userSchema);

// --- SCHEMAT WYJŚCIA (PINEZKI) ---
const outingSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Powiązanie z właścicielem
    userEmail: { type: String, required: true },
    name: String,
    city: String,
    location: String,
    plans: String,
    desc: String,
    coordinates: [Number], // [longitude, latitude]
    createdAt: { 
        type: Date, 
        default: Date.now, 
        expires: 10800 // Automatyczne usunięcie po 3h
    } 
});
const Outing = mongoose.model('Outing', outingSchema);

// --- FUNKCJA POMOCNICZA DO WYSYŁKI MAILI PRZEZ API BREVO ---
async function sendBrevoEmail(toEmail, subject, htmlContent) {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
            'accept': 'application/json',
            'api-key': process.env.BREVO_API_KEY,
            'content-type': 'application/json'
        },
        body: JSON.stringify({
            sender: { email: process.env.EMAIL_FROM || "noreply@drinkstop.pl", name: "Drink Stop" },
            to: [{ email: toEmail }],
            subject: subject,
            htmlContent: htmlContent
        })
    });

    if (!response.ok) {
        const errData = await response.json();
        throw new Error(JSON.stringify(errData));
    }
    return await response.json();
}

// --- 4. REJESTRACJA ---
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, age, city, password, photo, marketingConsent } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Ten e-mail jest już zajęty!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const token = crypto.randomBytes(32).toString('hex'); 

        const newUser = new User({
            name, 
            email, 
            age, 
            city, 
            password: hashedPassword, 
            verificationToken: token, 
            photo: photo || '',
            marketingConsent: marketingConsent || false
        });

        await newUser.save();

        const protocol = req.protocol;
        const host = req.get('host');
        const verificationLink = `${protocol}://${host}/api/verify/${token}`;
        
        await sendBrevoEmail(
            email,
            'Potwierdź swój adres e-mail w Drink Stop! 🍻',
            `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #f9f9f9; border-radius: 10px;">
                    <h2 style="color: #f5a623; margin-bottom: 10px;">Witaj w Drink Stop, ${name}!</h2>
                    <p style="color: #333; font-size: 15px;">Aby w pełni korzystać z aplikacji, aktywuj swoje konto:</p>
                    <a href="${verificationLink}" style="display: inline-block; padding: 12px 24px; background-color: #f5a623; color: #000; text-decoration: none; border-radius: 8px; font-weight: bold; margin: 20px 0;">Aktywuj konto 🍻</a>
                </div>
            `
        );

        res.status(201).json({ message: 'Konto utworzone! Sprawdź swoją skrzynkę e-mail, aby je aktywować.' });
    } catch (error) {
        console.error('Błąd rejestracji:', error);
        res.status(500).json({ message: 'Wystąpił błąd serwera.' });
    }
});

// --- 5. AKTYWACJA KONTA ---
app.get('/api/verify/:token', async (req, res) => {
    try {
        const user = await User.findOne({ verificationToken: req.params.token });
        if (!user) return res.status(400).send('<h1 style="color:red; text-align:center; margin-top:50px;">Błąd! Nieprawidłowy lub wygasły link.</h1>');

        user.isVerified = true;
        user.verificationToken = undefined;
        await user.save();

        res.send(`
            <div style="font-family: sans-serif; text-align: center; margin-top: 50px; background-color: #121212; color: white; height: 100vh; padding-top: 50px;">
                <h1 style="color: #90c83a;">Konto zostało aktywowane! ✅</h1>
                <p>Możesz teraz bezpiecznie zamknąć tę kartę i zalogować się w aplikacji.</p>
            </div>
        `);
    } catch (error) {
        res.status(500).send('Wystąpił błąd podczas aktywacji.');
    }
});

// --- 6. LOGOWANIE ---
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Nie znaleziono konta z tym adresem e-mail.' });
        }

        if (user.deletionRequested) {
            user.deletionRequested = false;
            user.deletionDate = null;
            await user.save();
        }

        if (!user.isVerified) {
            return res.status(403).json({ message: 'Konto nie jest aktywne! Kliknij w link wysłany na Twój e-mail.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Błędne hasło. Spróbuj ponownie.' });
        }
        
        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            message: 'Zalogowano pomyślnie!',
            token,
            user: { 
                id: user._id,
                name: user.name, 
                email: user.email,
                age: user.age, 
                city: user.city,
                status: user.status,
                interests: user.interests,
                desc: user.desc,
                photo: user.photo,
                eventCredits: user.eventCredits || 0
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd serwera podczas logowania.' });
    }
});

// --- 7. ZAPOMNIANE HASŁO ---
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Nie znaleziono konta.' });

        const token = crypto.randomBytes(32).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 15 * 60 * 1000; 
        await user.save();

        const resetLink = `${req.protocol}://${req.get('host')}/reset.html?token=${token}`;
        await sendBrevoEmail(email, 'Resetowanie hasła w Drink Stop 🔑', `<a href="${resetLink}">Zresetuj hasło</a>`);

        res.json({ message: 'Link do resetowania hasła został wysłany!' });
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera.' });
    }
});

// --- 8. ZAPIS NOWEGO HASŁA ---
app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        const user = await User.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ message: 'Token jest nieprawidłowy lub wygasł.' });

        user.password = await bcrypt.hash(newPassword, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.json({ message: 'Hasło zostało pomyślnie zmienione!' });
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera.' });
    }
});

// --- 9. AKTUALIZACJA PROFILU (ZABEZPIECZONA TOKENEM) ---
app.post('/api/update-profile', authMiddleware, async (req, res) => {
    try {
        const { name, age, city, interests, desc, photo } = req.body;
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });

        if (name) user.name = name;
        if (age) user.age = age;
        if (city) user.city = city;
        if (interests !== undefined) user.interests = interests;
        if (desc !== undefined) user.desc = desc;
        if (photo !== undefined) user.photo = photo;

        await user.save();

        res.json({ 
            message: 'Profil zaktualizowany pomyślnie!',
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                age: user.age,
                city: user.city,
                status: user.status,
                interests: user.interests,
                desc: user.desc,
                photo: user.photo,
                eventCredits: user.eventCredits || 0
            }
        });
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera.' });
    }
});

// --- 10. TESTOWY ENDPOINT PŁATNOŚCI (ZABEZPIECZONY TOKENEM) ---
app.post('/api/test-payment', authMiddleware, async (req, res) => {
    try {
        const { type, plan } = req.body; 
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });

        if (type === 'premium') {
            user.status = 'premium';
            await user.save();
            return res.json({ message: 'Konto Premium aktywowane!', status: 'premium' });
        } 
        
        if (type === 'b2b') {
            const addedCredits = plan === '1' ? 1 : plan === '5' ? 5 : plan === '10' ? 10 : 0;
            user.eventCredits = (user.eventCredits || 0) + addedCredits;
            await user.save();
            return res.json({ message: `Dodano ${addedCredits} oznaczeń eventowych.`, eventCredits: user.eventCredits });
        }

        res.status(400).json({ message: 'Nieznany typ płatności.' });
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera.' });
    }
});

// --- 11. ENDPOINTY DLA PINEZEK (WYJŚĆ) ---

app.get('/api/outings', async (req, res) => {
    try {
        const outings = await Outing.find({});
        res.json(outings);
    } catch (error) {
        res.status(500).json({ message: 'Błąd pobierania wyjść.' });
    }
});

// Tworzenie pinezki powiązane z zalogowanym użytkownikiem
app.post('/api/outings', authMiddleware, async (req, res) => {
    try {
        const { name, city, location, plans, desc, coordinates } = req.body;
        const user = await User.findById(req.user.id);

        const newOuting = new Outing({
            userId: user._id,
            userEmail: user.email,
            name, city, location, plans, desc, coordinates
        });

        await newOuting.save();
        res.status(201).json({ message: 'Wyjście opublikowane pomyślnie!', outing: newOuting });
    } catch (error) {
        res.status(500).json({ message: 'Błąd podczas publikowania wyjścia.' });
    }
});

// Usunięcie pinezki – sprawdza czy zalogowany użytkownik jest jej właścicielem!
app.delete('/api/outings/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const outing = await Outing.findById(id);

        if (!outing) {
            return res.status(404).json({ message: 'Nie znaleziono takiego wyjścia.' });
        }

        // Weryfikacja właściciela po ID użytkownika z tokenu JWT
        if (outing.userId.toString() !== req.user.id) {
            return res.status(403).json({ message: 'Nie masz uprawnień do usunięcia tej pinezki!' });
        }

        await Outing.findByIdAndDelete(id);
        res.json({ message: 'Pinezka została usunięta.' });
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera podczas usuwania.' });
    }
});

// --- WIADOMOŚCI I CHAT ---
const messageSchema = new mongoose.Schema({
    senderEmail: String,
    senderName: String,
    receiverEmail: String,
    receiverName: String, 
    message: String,
    type: { type: String, default: 'chat' }, 
    status: { type: String, default: 'pending' }, 
    deliveryStatus: { type: String, default: 'sent' },
    createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

app.post('/api/messages', async (req, res) => {
    try {
        const { senderEmail, senderName, receiverEmail, receiverName, message, type } = req.body;
        const newMessage = new Message({ senderEmail, senderName, receiverEmail, receiverName, message, type, deliveryStatus: 'sent' });
        await newMessage.save();
        res.status(201).json({ message: 'Wysłano!', data: newMessage });
    } catch (error) {
        res.status(500).json({ message: 'Błąd.' });
    }
});

app.get('/api/messages/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const messages = await Message.find({ $or: [{ receiverEmail: email }, { senderEmail: email }] }).sort({ createdAt: 1 });
        res.json(messages);
    } catch (error) {
        res.status(500).json({ message: 'Błąd.' });
    }
});

// --- POBIERANIE PROFILU ---
app.get('/api/user/:email', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.params.email });
        if (!user) return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
        res.json({
            name: user.name,
            age: user.age,
            city: user.city,
            interests: user.interests,
            desc: user.desc,
            photo: user.photo,
            eventCredits: user.eventCredits || 0
        });
    } catch (error) {
        res.status(500).json({ message: 'Błąd.' });
    }
});

// --- 12. START SERWERA ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Serwer działa! Otwórz: http://localhost:${PORT}`);
});
