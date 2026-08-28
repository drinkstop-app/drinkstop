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
    photo: { type: String, default: '' }
});
const User = mongoose.model('User', userSchema);

// --- SCHEMAT WYJŚCIA (PINEZKI) Z AUTOMATYCZNYM WYGASZANIAM PO GODZINIE ---
const outingSchema = new mongoose.Schema({
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
        expires: 3600 // Automatyczne usunięcie z bazy po 3600 sekundach (1 godzina)
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
        const { name, email, age, city, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Ten e-mail jest już zajęty!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const token = crypto.randomBytes(32).toString('hex'); 

        const newUser = new User({
            name, email, age, city, password: hashedPassword, verificationToken: token
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
                    
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0 20px 0;">
                    
                    <p style="color: #888; font-size: 12px; line-height: 1.5; margin: 0;">
                        Wiadomość została wygenerowana automatycznie, prosimy na nią nie odpowiadać.<br>
                        Jeśli to nie Ty zakładałeś konto w aplikacji Drink Stop, po prostu zignoruj tę wiadomość.
                    </p>
                </div>
            `
        );

        res.status(201).json({ message: 'Konto utworzone! Sprawdź swoją skrzynkę e-mail, aby je aktywować.' });

    } catch (error) {
        console.error('Błąd wysyłki e-maila:', error);
        res.status(500).json({ message: 'Wystąpił błąd serwera podczas wysyłania e-maila' });
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

        if (!user.isVerified) {
            return res.status(403).json({ message: 'Konto nie jest aktywne! Kliknij w link wysłany na Twój e-mail.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Błędne hasło. Spróbuj ponownie.' });
        }

        const token = jwt.sign({ id: user._id }, 'nasz_tajny_klucz_123', { expiresIn: '7d' });

        res.json({
            message: 'Zalogowano pomyślnie!',
            token,
            user: { 
                name: user.name, 
                age: user.age, 
                city: user.city,
                status: user.status,
                interests: user.interests,
                desc: user.desc,
                photo: user.photo
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
        
        if (!user) {
            return res.status(400).json({ message: 'Nie znaleziono konta z tym adresem e-mail.' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 15 * 60 * 1000; 
        await user.save();

        const protocol = req.protocol;
        const host = req.get('host');
        const resetLink = `${protocol}://${host}/reset.html?token=${token}`;

        await sendBrevoEmail(
            email,
            'Resetowanie hasła w Drink Stop 🔑',
            `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
                    <h2 style="color: #f5a623;">Resetowanie hasła</h2>
                    <p>Otrzymaliśmy prośbę o zresetowanie hasła do Twojego konta. Kliknij w poniższy przycisk:</p>
                    <a href="${resetLink}" style="display: inline-block; padding: 12px 24px; background-color: #f5a623; color: #000; text-decoration: none; border-radius: 8px; font-weight: bold; margin-top: 20px;">Zresetuj hasło 🔑</a>
                    <p style="margin-top: 20px; font-size: 12px; color: #888;">Link jest ważny przez 15 minut.</p>
                </div>
            `
        );

        res.json({ message: 'Link do resetowania hasła został wysłany na Twój e-mail!' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd serwera.' });
    }
});

// --- 8. ZAPIS NOWEGO HASŁA ---
app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Token jest nieprawidłowy lub wygasł.' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.json({ message: 'Hasło zostało pomyślnie zmienione! Możesz się teraz zalogować.' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd serwera.' });
    }
});

// --- 9. AKTUALIZACJA PROFILU ---
app.post('/api/update-profile', async (req, res) => {
    try {
        const { email, name, age, city, interests, desc, photo } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
        }

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
                name: user.name,
                age: user.age,
                city: user.city,
                status: user.status,
                interests: user.interests,
                desc: user.desc,
                photo: user.photo
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd serwera podczas aktualizacji profilu.' });
    }
});

// --- 10. AKTYWACJA PREMIUM ---
app.post('/api/activate-premium', async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'Nie znaleziono użytkownika.' });
        }

        user.status = 'premium';
        await user.save();

        res.json({ message: 'Konto zostało pomyślnie zaktualizowane do wersji Premium! 👑', status: 'premium' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd podczas aktywacji pakietu.' });
    }
});

// --- 11. ENDPOINTY DLA PINEZEK (WYJŚĆ) ---

// Pobieranie wszystkich aktywnych wyjść
app.get('/api/outings', async (req, res) => {
    try {
        const outings = await Outing.find({});
        res.json(outings);
    } catch (error) {
        res.status(500).json({ message: 'Błąd pobierania wyjść.' });
    }
});

// Tworzenie nowego wyjścia
app.post('/api/outings', async (req, res) => {
    try {
        const { userEmail, name, city, location, plans, desc, coordinates } = req.body;
        
        const newOuting = new Outing({
            userEmail, name, city, location, plans, desc, coordinates
        });

        await newOuting.save();
        res.status(201).json({ message: 'Wyjście opublikowane pomyślnie!', outing: newOuting });
    } catch (error) {
        res.status(500).json({ message: 'Błąd podczas publikowania wyjścia.' });
    }
});

// Ręczne usuwanie wyjścia (tylko przez autora)
app.delete('/api/outings/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { email } = req.body;

        const outing = await Outing.findById(id);
        if (!outing) {
            return res.status(404).json({ message: 'Nie znaleziono takiego wyjścia.' });
        }

        if (outing.userEmail !== email) {
            return res.status(403).json({ message: 'Nie masz uprawnień do usunięcia tej pinezki!' });
        }

        await Outing.findByIdAndDelete(id);
        res.json({ message: 'Pinezka została usunięta.' });
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera podczas usuwania.' });
    }
});

// --- 12. START SERWERA ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Serwer działa! Otwórz: http://localhost:${PORT}`);
});
