/**
 * POST
 * 
 * Headers 
 * Content-Type: application/json
 * x-api-key: f7a2e5849c0d3b16e5f8d9c2a0b4e7f1d2c3b4a5
 * 
 * body
 * {"url":"https://domain.com"}
 */



const express = require('express');
const cors = require('cors');
const puppeteer = require('puppeteer');
const fs = require('fs');
const app = express();
const crypto = require('crypto');

app.use(cors());
app.use(express.json());

const allowedOrigin = 'https://axetool.devpoint.me';
const API_KEY = process.env.API_KEY || 'f7a2e5849c0d3b16e5f8d9c2a0b4e7f1d2c3b4a5';

const corsOptions = {
  origin: function (origin, callback) {
    if (origin === allowedOrigin || !origin) { // !origin позволяет запросам без заголовка Origin (например, Postman) проходить для тестирования
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
};

app.use(cors(corsOptions));
app.use(express.json());

const checkAccess = (req, res, next) => {
  // ПРОВЕРКА №1: Запрос из браузера с разрешенного домена
  const requestOrigin = req.get('Origin');
  if (requestOrigin === allowedOrigin) {
    return next(); // Доступ разрешен
  }

  // ПРОВЕРКА №2: Серверный запрос с правильным API-ключом
  const userApiKey = req.get('x-api-key');
  if (userApiKey) {
    try {
      const keyBuffer = Buffer.from(API_KEY, 'utf8');
      const userKeyBuffer = Buffer.from(userApiKey, 'utf8');
      
      // Безопасное сравнение ключей для защиты от атак по времени
      if (keyBuffer.length === userKeyBuffer.length && crypto.timingSafeEqual(keyBuffer, userKeyBuffer)) {
        return next(); // Доступ разрешен
      }
    } catch (e) {
      // Ошибка формата ключа, просто проваливаемся до отказа в доступе
    }
  }
  
  // Если ни одна проверка не пройдена, отклоняем запрос
  return res.status(403).json({ error: 'Forbidden: Access denied. Invalid origin or missing/incorrect API key.' });
};

app.get('/api/scan', (req, res) => {
  console.log('[ROUTE /api/scan GET] Received a GET request.');
  res.send('Server is working! ✅');
});

app.post('/api/scan', checkAccess, async (req, res) => {
  const { url, limit } = req.body;
  // let limit = '';

  // if(req.limit !== undefined){
  //   limit = req.limit;
  // }

  if (!url || !url.startsWith('http')) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  let browser;
  try {
    browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 60000 });

    const axeSource = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
    await page.evaluate(axeSource);

    const data = await page.evaluate(async () => {
      // @ts-ignore
      return await axe.run(document, {
        // runOnly: {
        //   type: 'tag',
        //   values: ['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22a','wcag22aa','best-practice']  //'wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'
        // }
      });
    });

    //return res.json({'data':data});

    const sections = ["violations"]; //"inapplicable", "passes", "incomplete", "violations"
    //const impacts = ["Critical", "Serious", "Moderate", "Minor", null];
    let summury = {};
    let results = {};

    sections.forEach(section => {
      summury = {
          "critical": 0,
          "serious": 0,
          "moderate": 0,
          "minor": 0,
          "null": 0
      };

      results = {
          "critical": [],
          "serious": [],
          "moderate": [],
          "minor": [],
          "null": []
      };


      if (data[section]) {
          data[section].forEach(item => {

              item.nodes.forEach(el => {

                if(limit == 'all' || summury[el.impact]<3){

                  el.helpUrl = item.helpUrl;
                  el.description = item.description;
                  el.help = item.help;
                  el.tags = item.tags;

                  results[el.impact].push(el);
                }
                summury[el.impact]++;
              });
          });
      }
    });
    
    return res.json({'summury':summury, 'results': results});

  } catch (error) {
    console.error("Puppeteer error:", error);
    return res.status(500).json({ error: "Failed to scan the page.", details: error.message });
    
  } finally {
    if (browser) {
      await browser.close();
    }
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});