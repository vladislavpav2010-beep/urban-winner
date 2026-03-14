<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>TON BATTLE - EXCLUSIVE EDITION</title>
    
    <script src="https://telegram.org/js/telegram-web-app.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Outfit:wght@700;800;900&display=swap" rel="stylesheet">
    
    <style>
        /* =========================================
           1. ПЕРЕМЕННЫЕ И БАЗОВЫЕ НАСТРОЙКИ
           ========================================= */
        :root {
            /* Палитра */
            --bg-main: #090a0f;
            --bg-card: #13151b;
            --bg-card-hover: #1a1d24;
            --accent: #0088cc;
            --accent-glow: rgba(0, 136, 204, 0.4);
            --gold: #ffb800;
            --gold-glow: rgba(255, 184, 0, 0.3);
            --text-main: #ffffff;
            --text-muted: #798293;
            --border: #20242f;
            --green: #20c976;
            --red: #ff3b3b;
            
            /* Цвета рулетки */
            --color-blue: #3b70ff;
            --color-red: #ff3b5c;
            
            /* Размеры и отступы */
            --radius-sm: 12px;
            --radius-md: 18px;
            --radius-lg: 24px;
            --radius-round: 50%;
            --safe-top: env(safe-area-inset-top, 0px);
            --safe-bottom: env(safe-area-inset-bottom, 0px);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            user-select: none;
            -webkit-tap-highlight-color: transparent;
            font-family: 'Manrope', sans-serif;
        }

        body {
            background-color: var(--bg-main);
            color: var(--text-main);
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        /* Скрываем скроллбары, но оставляем прокрутку */
        ::-webkit-scrollbar { display: none; }
        .scrollable { overflow-y: auto; scrollbar-width: none; }

        /* Вспомогательные классы */
        .flex-row { display: flex; align-items: center; }
        .flex-between { display: flex; align-items: center; justify-content: space-between; }
        .flex-center { display: flex; align-items: center; justify-content: center; }
        .text-outfit { font-family: 'Outfit', sans-serif; }
        .text-gradient { background: linear-gradient(90deg, #fff, #a0a5b1); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }

        /* =========================================
           2. HEADER (ШАПКА)
           ========================================= */
        header {
            position: fixed;
            top: 0; left: 0; right: 0;
            padding: calc(var(--safe-top) + 12px) 16px 12px;
            background: rgba(9, 10, 15, 0.85);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border);
            z-index: 1000;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .balance-widget {
            background: linear-gradient(180deg, var(--bg-card), #0d0f14);
            border: 1px solid var(--border);
            padding: 8px 16px;
            border-radius: 100px;
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.4);
            cursor: pointer;
            transition: 0.2s;
        }
        .balance-widget:active { transform: scale(0.95); }
        .balance-widget span { font-family: 'Outfit'; font-weight: 800; font-size: 17px; color: var(--text-main); letter-spacing: 0.5px;}
        .balance-widget .curr { color: var(--accent); font-size: 14px; }

        .profile-mini {
            display: flex;
            align-items: center;
            gap: 10px;
            background: var(--bg-card);
            padding: 4px 6px 4px 14px;
            border-radius: 100px;
            border: 1px solid var(--border);
        }
        .profile-mini .name { font-weight: 700; font-size: 13px; max-width: 80px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .profile-mini .ava { width: 32px; height: 32px; border-radius: var(--radius-round); background: var(--accent); font-weight: 800; font-size: 14px; }

        /* =========================================
           3. BOTTOM NAVIGATION (МЕНЮ)
           ========================================= */
        nav {
            position: fixed;
            bottom: 0; left: 0; right: 0;
            background: rgba(13, 15, 20, 0.95);
            backdrop-filter: blur(20px);
            padding-bottom: var(--safe-bottom);
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: space-around;
            z-index: 1000;
        }

        .nav-item {
            flex: 1;
            padding: 12px 0 16px;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 6px;
            color: var(--text-muted);
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .nav-item svg { width: 24px; height: 24px; fill: currentColor; transition: 0.3s; }
        .nav-item.active { color: var(--accent); }
        .nav-item.active svg { transform: translateY(-4px); filter: drop-shadow(0 4px 8px var(--accent-glow)); }

        /* =========================================
           4. ОСНОВНОЙ КОНТЕЙНЕР И ЭКРАНЫ
           ========================================= */
        .main-content {
            flex: 1;
            margin-top: calc(var(--safe-top) + 65px);
            margin-bottom: calc(var(--safe-bottom) + 70px);
            position: relative;
        }

        .screen {
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            padding: 16px;
            opacity: 0;
            pointer-events: none;
            transform: translateY(20px) scale(0.98);
            transition: all 0.4s cubic-bezier(0.1, 0.9, 0.2, 1);
        }
        .screen.active {
            opacity: 1;
            pointer-events: auto;
            transform: translateY(0) scale(1);
        }

        /* Общие компоненты */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 20px;
            margin-bottom: 16px;
        }
        .btn-primary {
            width: 100%; padding: 16px;
            background: var(--accent);
            color: #fff; border: none;
            border-radius: var(--radius-md);
            font-family: 'Outfit'; font-weight: 800; font-size: 16px;
            cursor: pointer; transition: 0.2s;
            box-shadow: 0 8px 20px var(--accent-glow);
        }
        .btn-primary:active { transform: scale(0.97); box-shadow: 0 4px 10px var(--accent-glow); }
        
        .btn-secondary {
            padding: 12px 20px;
            background: #1c1f28;
            color: var(--text-main); border: 1px solid var(--border);
            border-radius: var(--radius-md);
            font-weight: 700; font-size: 14px;
            cursor: pointer; transition: 0.2s;
        }
        .btn-secondary:active { background: #232733; }

        /* =========================================
           5. ЭКРАН 1: БИТВА (РУЛЕТКА)
           ========================================= */
        .battle-banner {
            background: linear-gradient(135deg, #182035, var(--bg-card));
            border-radius: var(--radius-lg);
            padding: 16px; margin-bottom: 24px;
            border: 1px solid #2a344a;
            position: relative; overflow: hidden;
        }
        .battle-banner::before {
            content: ''; position: absolute; right: -20px; top: -20px; width: 100px; height: 100px;
            background: var(--accent); filter: blur(50px); opacity: 0.3;
        }

        /* Рулетка */
        .wheel-wrapper { position: relative; width: 280px; height: 280px; margin: 0 auto 30px; }
        .wheel-pointer {
            position: absolute; top: -15px; left: 50%; transform: translateX(-50%);
            width: 0; height: 0; z-index: 10;
            border-left: 14px solid transparent; border-right: 14px solid transparent; border-top: 24px solid var(--text-main);
            filter: drop-shadow(0 4px 6px rgba(0,0,0,0.5));
        }
        .wheel-outer {
            width: 100%; height: 100%; border-radius: var(--radius-round);
            border: 10px solid #1a1d24;
            box-shadow: 0 0 40px rgba(0,0,0,0.6), inset 0 0 20px rgba(0,0,0,0.8);
            background: conic-gradient(var(--color-blue) 0% 50%, var(--color-red) 50% 100%);
            transition: transform 7s cubic-bezier(0.2, 0, 0, 1);
        }
        .wheel-inner {
            position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
            width: 120px; height: 120px; border-radius: var(--radius-round);
            background: var(--bg-main); border: 8px solid #1a1d24;
            display: flex; flex-direction: column; align-items: center; justify-content: center;
            box-shadow: 0 10px 20px rgba(0,0,0,0.5);
        }
        .wheel-timer-val { font-family: 'Outfit'; font-size: 38px; font-weight: 900; line-height: 1; }
        .wheel-timer-lbl { font-size: 10px; font-weight: 800; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }

        /* Ставки и Пулы */
        .pools-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; }
        .pool-card { background: var(--bg-card); border: 1px solid var(--border); padding: 14px; border-radius: var(--radius-md); text-align: center; }
        .pool-card .lbl { font-size: 11px; font-weight: 800; color: var(--text-muted); text-transform: uppercase; }
        .pool-card .val { font-family: 'Outfit'; font-size: 22px; font-weight: 900; margin-top: 5px; }
        .pool-blue .val { color: var(--color-blue); text-shadow: 0 0 15px rgba(59, 112, 255, 0.3); }
        .pool-red .val { color: var(--color-red); text-shadow: 0 0 15px rgba(255, 59, 92, 0.3); }

        .progress-wrap { height: 12px; background: #1a1d24; border-radius: 20px; display: flex; overflow: hidden; margin-bottom: 24px; border: 1px solid var(--border); }
        .progress-blue { background: var(--color-blue); width: 50%; transition: width 0.5s ease; box-shadow: 0 0 10px var(--color-blue); }
        .progress-red { background: var(--color-red); width: 50%; transition: width 0.5s ease; box-shadow: 0 0 10px var(--color-red); }

        /* Ввод ставки */
        .bet-controls { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 16px; margin-bottom: 24px; }
        .bet-input-row { display: flex; align-items: center; justify-content: space-between; margin: 15px 0; background: #0d0f14; border-radius: var(--radius-md); padding: 5px; border: 1px solid var(--border); }
        .btn-circle { width: 45px; height: 45px; border-radius: var(--radius-md); background: #1a1d24; border: none; color: #fff; font-size: 24px; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: 0.2s;}
        .btn-circle:active { background: #252a36; transform: scale(0.9); }
        .bet-input-row input { flex: 1; background: transparent; border: none; color: #fff; font-family: 'Outfit'; font-size: 28px; font-weight: 900; text-align: center; outline: none; width: 100%; }
        
        .chips-scroll { display: flex; gap: 8px; overflow-x: auto; padding-bottom: 5px; margin-bottom: 20px; }
        .chip { padding: 10px 20px; background: #1a1d24; border: 1px solid var(--border); border-radius: 12px; font-family: 'Outfit'; font-weight: 800; font-size: 14px; color: var(--text-muted); cursor: pointer; white-space: nowrap; transition: 0.2s;}
        .chip:active { transform: scale(0.95); }
        .chip.active { background: var(--accent); color: #fff; border-color: var(--accent); }

        /* Выбор цвета */
        .color-btns { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        .btn-color { padding: 18px; border-radius: var(--radius-md); border: none; color: #fff; font-family: 'Outfit'; font-weight: 900; font-size: 18px; cursor: pointer; display: flex; flex-direction: column; align-items: center; gap: 4px; transition: 0.2s;}
        .btn-color:active { transform: scale(0.96); }
        .btn-color.blue { background: linear-gradient(135deg, #4b7dff, #2955cc); box-shadow: 0 8px 25px rgba(59, 112, 255, 0.4); }
        .btn-color.red { background: linear-gradient(135deg, #ff5e79, #cc2340); box-shadow: 0 8px 25px rgba(255, 59, 92, 0.4); }
        .btn-color span { font-size: 11px; font-family: 'Manrope'; font-weight: 700; opacity: 0.8; }

        /* Живая лента */
        .live-feed { margin-top: 30px; }
        .feed-title { display: flex; align-items: center; gap: 8px; font-size: 12px; font-weight: 800; color: var(--text-muted); margin-bottom: 12px; text-transform: uppercase; }
        .feed-title .dot { width: 8px; height: 8px; background: var(--green); border-radius: 50%; box-shadow: 0 0 8px var(--green); animation: pulse 1.5s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
        .feed-list { display: flex; flex-direction: column; gap: 8px; }
        .feed-item { background: var(--bg-card); border: 1px solid var(--border); padding: 10px 14px; border-radius: 12px; display: flex; align-items: center; justify-content: space-between; animation: slideInFeed 0.3s ease forwards; }
        @keyframes slideInFeed { from { opacity: 0; transform: translateX(-20px); } to { opacity: 1; transform: translateX(0); } }
        .feed-user { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 13px; }
        .feed-ava { width: 24px; height: 24px; border-radius: 50%; background: #333; display: flex; align-items: center; justify-content: center; font-size: 10px; }
        .feed-amt { font-family: 'Outfit'; font-weight: 800; }
        .feed-amt.blue { color: var(--color-blue); }
        .feed-amt.red { color: var(--color-red); }

        /* =========================================
           6. ЭКРАН 2: МАГАЗИН (SHOP) - ВОЗВРАЩЕНИЕ ЛЕГЕНДЫ
           ========================================= */
        .shop-header { text-align: center; margin-bottom: 24px; }
        .shop-header h1 { font-family: 'Outfit'; font-size: 32px; font-weight: 900; margin-bottom: 8px; }
        .shop-header p { color: var(--text-muted); font-size: 14px; }

        .shop-categories { display: flex; gap: 10px; overflow-x: auto; padding-bottom: 10px; margin-bottom: 20px; }
        .cat-btn { padding: 10px 20px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 100px; font-weight: 800; font-size: 13px; color: var(--text-muted); white-space: nowrap; transition: 0.2s; }
        .cat-btn.active { background: #fff; color: #000; border-color: #fff; }

        .shop-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; padding-bottom: 20px; }
        .shop-item { background: linear-gradient(180deg, var(--bg-card), #0d0f14); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 16px; text-align: center; position: relative; overflow: hidden; transition: 0.3s; }
        .shop-item:hover { border-color: var(--accent); transform: translateY(-3px); }
        .item-icon { font-size: 48px; margin-bottom: 12px; filter: drop-shadow(0 10px 15px rgba(0,0,0,0.5)); }
        .item-name { font-weight: 800; font-size: 15px; margin-bottom: 4px; }
        .item-desc { font-size: 11px; color: var(--text-muted); margin-bottom: 16px; min-height: 30px;}
        .item-price { font-family: 'Outfit'; font-size: 18px; font-weight: 900; color: var(--gold); margin-bottom: 12px; display: flex; align-items: center; justify-content: center; gap: 4px; }
        .btn-buy { width: 100%; padding: 12px; background: rgba(0, 136, 204, 0.1); border: 1px solid var(--accent); color: var(--accent); border-radius: var(--radius-md); font-weight: 800; transition: 0.2s; }
        .btn-buy:active { background: var(--accent); color: #fff; }
        .item-owned .btn-buy { background: rgba(32, 201, 118, 0.1); border-color: var(--green); color: var(--green); }

        /* =========================================
           7. ЭКРАН 3: ТОП (ЛИДЕРЫ)
           ========================================= */
        .top-season-card { background: linear-gradient(180deg, #1f1a0e, var(--bg-card)); border: 1px solid #3d3118; border-radius: var(--radius-lg); padding: 30px 20px; text-align: center; margin-bottom: 30px; position: relative; }
        .top-cup { font-size: 70px; line-height: 1; margin-bottom: 15px; filter: drop-shadow(0 0 30px var(--gold-glow)); animation: float 3s ease-in-out infinite; }
        @keyframes float { 0% { transform: translateY(0px); } 50% { transform: translateY(-10px); } 100% { transform: translateY(0px); } }
        
        .podium { display: flex; align-items: flex-end; justify-content: center; gap: 10px; margin-bottom: 30px; margin-top: 20px;}
        .podium-place { display: flex; flex-direction: column; align-items: center; width: 30%; }
        .podium-ava { width: 50px; height: 50px; border-radius: 50%; background: var(--bg-card); border: 2px solid var(--border); display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 20px; margin-bottom: -15px; z-index: 2; position: relative; }
        .podium-bar { width: 100%; background: var(--bg-card); border-radius: 12px 12px 0 0; border: 1px solid var(--border); border-bottom: none; text-align: center; padding: 25px 5px 10px; font-family: 'Outfit'; font-weight: 900; font-size: 24px; color: rgba(255,255,255,0.2); }
        .podium-name { font-size: 11px; font-weight: 800; margin-top: 8px; text-align: center; overflow: hidden; text-overflow: ellipsis; width: 100%; white-space: nowrap; }
        .podium-score { font-family: 'Outfit'; font-size: 13px; font-weight: 800; color: var(--accent); }
        
        .podium-1 .podium-bar { height: 120px; background: linear-gradient(180deg, rgba(255, 184, 0, 0.15), var(--bg-card)); border-color: var(--gold); color: var(--gold); }
        .podium-1 .podium-ava { border-color: var(--gold); width: 64px; height: 64px; margin-bottom: -20px; box-shadow: 0 0 20px var(--gold-glow); }
        .podium-2 .podium-bar { height: 90px; background: linear-gradient(180deg, rgba(192, 192, 192, 0.15), var(--bg-card)); border-color: #c0c0c0; color: #c0c0c0; }
        .podium-2 .podium-ava { border-color: #c0c0c0; }
        .podium-3 .podium-bar { height: 70px; background: linear-gradient(180deg, rgba(205, 127, 50, 0.15), var(--bg-card)); border-color: #cd7f32; color: #cd7f32; }
        .podium-3 .podium-ava { border-color: #cd7f32; }

        .leader-list { display: flex; flex-direction: column; gap: 10px; }
        .leader-row { background: var(--bg-card); border: 1px solid var(--border); padding: 12px 16px; border-radius: var(--radius-md); display: flex; align-items: center; gap: 15px; }
        .leader-rank { font-family: 'Outfit'; font-size: 16px; font-weight: 900; color: var(--text-muted); width: 20px; text-align: center; }
        .leader-info { flex: 1; font-weight: 700; font-size: 14px; }
        .leader-val { font-family: 'Outfit'; font-weight: 800; color: var(--text-main); }

        /* =========================================
           8. ЭКРАН 4: ПРОФИЛЬ
           ========================================= */
        .profile-header-main { text-align: center; padding: 20px 0 30px; position: relative; }
        .p-ava-huge { width: 100px; height: 100px; border-radius: 30px; background: linear-gradient(135deg, var(--accent), #1a4b8c); margin: 0 auto 15px; display: flex; align-items: center; justify-content: center; font-size: 40px; font-weight: 900; color: #fff; box-shadow: 0 15px 35px var(--accent-glow); border: 4px solid var(--bg-main); transform: rotate(-5deg); transition: 0.3s; }
        .p-ava-huge:active { transform: rotate(0deg) scale(0.95); }
        .p-name-huge { font-family: 'Outfit'; font-size: 28px; font-weight: 900; letter-spacing: 0.5px; }
        .p-id-lbl { background: var(--bg-card); border: 1px solid var(--border); padding: 4px 12px; border-radius: 100px; font-size: 11px; font-weight: 800; color: var(--text-muted); display: inline-block; margin-top: 8px; }

        .wallet-block { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 24px; margin-bottom: 20px; text-align: center; }
        .wallet-block .lbl { font-size: 12px; font-weight: 800; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }
        .wallet-block .bal { font-family: 'Outfit'; font-size: 48px; font-weight: 900; margin: 10px 0 20px; line-height: 1; }
        .action-btns { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        
        .promo-block { display: flex; gap: 10px; margin-bottom: 24px; }
        .promo-block input { flex: 1; background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 16px; color: #fff; font-weight: 700; outline: none; font-size: 14px; }
        .promo-block button { background: var(--text-main); color: #000; border: none; padding: 0 24px; border-radius: var(--radius-md); font-weight: 900; font-family: 'Outfit'; cursor: pointer; }

        .section-title { font-family: 'Outfit'; font-size: 20px; font-weight: 800; margin-bottom: 15px; display: flex; align-items: center; justify-content: space-between; }
        
        .inv-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 30px; }
        .inv-slot { background: var(--bg-card); border: 1px solid var(--border); aspect-ratio: 1; border-radius: 16px; display: flex; align-items: center; justify-content: center; font-size: 28px; position: relative; }
        .inv-slot.empty { background: rgba(255,255,255,0.02); border: 1px dashed rgba(255,255,255,0.1); color: rgba(255,255,255,0.1); }
        .inv-badge { position: absolute; top: -5px; right: -5px; background: var(--accent); color: #fff; font-size: 9px; font-weight: 900; padding: 2px 6px; border-radius: 10px; border: 2px solid var(--bg-main); }

        .hist-list { display: flex; flex-direction: column; gap: 0; }
        .hist-item { padding: 16px 0; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
        .hist-item:last-child { border-bottom: none; }
        .h-l b { display: block; font-size: 14px; font-weight: 700; margin-bottom: 4px; }
        .h-l span { font-size: 11px; color: var(--text-muted); }
        .h-r { font-family: 'Outfit'; font-weight: 800; font-size: 16px; }
        .h-r.plus { color: var(--green); }
        .h-r.minus { color: var(--text-main); }

        /* =========================================
           9. МОДАЛКИ И УВЕДОМЛЕНИЯ (TOASTS)
           ========================================= */
        .modal-bg { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); z-index: 9999; display: flex; align-items: center; justify-content: center; opacity: 0; pointer-events: none; transition: 0.3s; }
        .modal-bg.show { opacity: 1; pointer-events: auto; }
        .modal-box { background: var(--bg-card); border: 1px solid var(--border); width: 90%; max-width: 360px; border-radius: var(--radius-lg); padding: 24px; transform: scale(0.9); transition: 0.3s cubic-bezier(0.17, 0.89, 0.32, 1.28); }
        .modal-bg.show .modal-box { transform: scale(1); }
        .modal-title { font-family: 'Outfit'; font-size: 24px; font-weight: 900; margin-bottom: 10px; text-align: center; }
        .modal-body { color: var(--text-muted); font-size: 14px; text-align: center; margin-bottom: 24px; line-height: 1.5; }
        .modal-input { width: 100%; background: #0d0f14; border: 1px solid var(--border); border-radius: var(--radius-md); padding: 16px; color: #fff; font-family: 'Outfit'; font-size: 18px; font-weight: 800; outline: none; margin-bottom: 15px; text-align: center; }

        .toast-container { position: fixed; top: calc(var(--safe-top) + 80px); left: 50%; transform: translateX(-50%); z-index: 10000; display: flex; flex-direction: column; gap: 10px; align-items: center; pointer-events: none; }
        .toast { background: rgba(255,255,255,0.95); color: #000; padding: 12px 20px; border-radius: 100px; font-weight: 800; font-size: 13px; display: flex; align-items: center; gap: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); animation: toastIn 0.3s cubic-bezier(0.17, 0.89, 0.32, 1.28) forwards; }
        @keyframes toastIn { from { opacity: 0; transform: translateY(-20px) scale(0.9); } to { opacity: 1; transform: translateY(0) scale(1); } }
        .toast.hide { animation: toastOut 0.3s ease forwards; }
        @keyframes toastOut { to { opacity: 0; transform: translateY(-10px) scale(0.9); } }
    </style>
</head>
<body>

    <header>
        <div class="profile-mini">
            <div class="ava" id="hdr-ava">U</div>
            <div class="name" id="hdr-name">Игрок</div>
        </div>
        <div class="balance-widget" onclick="switchTab('profile')">
            <span id="hdr-bal">0.00</span>
            <span class="curr">TON</span>
        </div>
    </header>

    <div class="main-content scrollable">
        
        <div id="tab-battle" class="screen active">
            <div class="battle-banner">
                <div style="position: relative; z-index: 2;">
                    <div style="font-size: 10px; font-weight: 800; color: rgba(255,255,255,0.6); letter-spacing: 1px; margin-bottom: 4px;">СЕЗОННЫЙ ПУЛ</div>
                    <div style="font-family: 'Outfit'; font-size: 28px; font-weight: 900; color: #fff;">15,000 <span style="color:var(--accent)">TON</span></div>
                </div>
            </div>

            <div class="wheel-wrapper">
                <div class="wheel-pointer"></div>
                <div class="wheel-outer" id="roulette-wheel"></div>
                <div class="wheel-inner">
                    <span class="wheel-timer-val" id="r-timer">15</span>
                    <span class="wheel-timer-lbl">Секунд</span>
                </div>
            </div>

            <div class="pools-grid">
                <div class="pool-card pool-blue">
                    <div class="lbl">Blue Pool</div>
                    <div class="val" id="pool-blue-val">0.00</div>
                </div>
                <div class="pool-card pool-red">
                    <div class="lbl">Red Pool</div>
                    <div class="val" id="pool-red-val">0.00</div>
                </div>
            </div>

            <div class="progress-wrap">
                <div class="progress-blue" id="bar-blue"></div>
                <div class="progress-red" id="bar-red"></div>
            </div>

            <div class="bet-controls">
                <div class="flex-between">
                    <span style="font-size: 12px; font-weight: 800; color: var(--text-muted);">СУММА СТАВКИ</span>
                    <span style="font-size: 12px; font-weight: 800; color: var(--accent); cursor: pointer;" onclick="setBet('max')">MAX</span>
                </div>
                <div class="bet-input-row">
                    <button class="btn-circle" onclick="adjBet(-1)">-</button>
                    <input type="number" id="bet-amt" value="1.00" step="0.1">
                    <button class="btn-circle" onclick="adjBet(1)">+</button>
                </div>
                <div class="chips-scroll">
                    <div class="chip" onclick="setBet(1)">1 TON</div>
                    <div class="chip" onclick="setBet(5)">5 TON</div>
                    <div class="chip" onclick="setBet(10)">10 TON</div>
                    <div class="chip" onclick="setBet(50)">50 TON</div>
                    <div class="chip" onclick="setBet(100)">100 TON</div>
                </div>
                
                <div class="color-btns">
                    <button class="btn-color blue" onclick="placeBet('blue')">
                        BLUE <span>x2 Payout</span>
                    </button>
                    <button class="btn-color red" onclick="placeBet('red')">
                        RED <span>x2 Payout</span>
                    </button>
                </div>
            </div>

            <div class="live-feed">
                <div class="feed-title"><div class="dot"></div> LIVE СТАВКИ</div>
                <div class="feed-list" id="live-feed-list">
                    </div>
            </div>
        </div>

        <div id="tab-shop" class="screen">
            <div class="shop-header">
                <h1>Магазин</h1>
                <p>Выделяйся среди других игроков</p>
            </div>

            <div class="shop-categories">
                <div class="cat-btn active">⚡ Аватары</div>
                <div class="cat-btn">🎨 Темы (Скоро)</div>
                <div class="cat-btn">🚀 Бусты (Скоро)</div>
            </div>

            <div class="shop-grid" id="shop-grid">
                </div>
        </div>

        <div id="tab-top" class="screen">
            <div class="top-season-card">
                <div class="top-cup">🏆</div>
                <div style="font-size: 11px; font-weight: 800; color: var(--text-muted); letter-spacing: 1px; margin-bottom: 5px;">КОНЕЦ СЕЗОНА ЧЕРЕЗ</div>
                <div style="font-family: 'Outfit'; font-size: 36px; font-weight: 900; color: #fff; line-height: 1;" id="season-time">29д 14:05</div>
            </div>

            <div class="podium">
                <div class="podium-place podium-2">
                    <div class="podium-ava">S</div>
                    <div class="podium-bar">2</div>
                    <div class="podium-name">Solana_Boy</div>
                    <div class="podium-score">850 TON</div>
                </div>
                <div class="podium-place podium-1">
                    <div class="podium-ava">W</div>
                    <div class="podium-bar">1</div>
                    <div class="podium-name">WhaleKing</div>
                    <div class="podium-score">1420 TON</div>
                </div>
                <div class="podium-place podium-3">
                    <div class="podium-ava">D</div>
                    <div class="podium-bar">3</div>
                    <div class="podium-name">DurovFan</div>
                    <div class="podium-score">530 TON</div>
                </div>
            </div>

            <div class="leader-list">
                <div class="leader-row"><div class="leader-rank">4</div><div class="leader-info">CryptoNinja</div><div class="leader-val">410.5</div></div>
                <div class="leader-row"><div class="leader-rank">5</div><div class="leader-info">TonMaster</div><div class="leader-val">380.0</div></div>
                <div class="leader-row"><div class="leader-rank">6</div><div class="leader-info">Lucky777</div><div class="leader-val">290.2</div></div>
            </div>
        </div>

        <div id="tab-profile" class="screen">
            <div class="profile-header-main">
                <div class="p-ava-huge" id="prof-ava">U</div>
                <div class="p-name-huge" id="prof-name">Username</div>
                <div class="p-id-lbl" id="prof-id">ID: 00000000</div>
            </div>

            <div class="wallet-block">
                <div class="lbl">Доступно для вывода</div>
                <div class="bal"><span id="prof-bal">0.00</span> <span style="font-size: 20px; color: var(--accent);">TON</span></div>
                <div class="action-btns">
                    <button class="btn-primary" onclick="showModal('deposit')">ПОПОЛНИТЬ</button>
                    <button class="btn-secondary" onclick="showModal('withdraw')">ВЫВЕСТИ</button>
                </div>
            </div>

            <div class="promo-block">
                <input type="text" id="promo-input" placeholder="Промокод...">
                <button onclick="activatePromo()">ОК</button>
            </div>

            <div class="section-title">
                Инвентарь <span style="font-size: 13px; color: var(--text-muted); font-weight: 700;">МАКС 8</span>
            </div>
            <div class="inv-grid" id="inv-grid">
                </div>

            <div class="section-title" style="margin-top: 20px;">История транзакций</div>
            <div class="card" style="padding: 0 20px;">
                <div class="hist-list" id="hist-list">
                    </div>
            </div>
        </div>

    </div>

    <nav>
        <div class="nav-item active" onclick="switchTab('battle', this)">
            <svg viewBox="0 0 24 24"><path d="M14.06 9.02l.92.92L5.92 19H5v-.92l9.06-9.06M17.66 3c-.25 0-.51.1-.7.29l-1.83 1.83 3.75 3.75 1.83-1.83c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.2-.2-.45-.29-.71-.29zm-3.6 3.19L3 17.25V21h3.75L17.81 9.94l-3.75-3.75z"/></svg>
            Батл
        </div>
        <div class="nav-item" onclick="switchTab('shop', this)">
            <svg viewBox="0 0 24 24"><path d="M7 18c-1.1 0-1.99.9-1.99 2S5.9 22 7 22s2-.9 2-2-.9-2-2-2zM1 2v2h2l3.6 7.59-1.35 2.45c-.16.28-.25.61-.25.96 0 1.1.9 2 2 2h12v-2H7.42c-.14 0-.25-.11-.25-.25l.03-.12.9-1.63h7.45c.75 0 1.41-.41 1.75-1.03l3.58-6.49c.08-.14.12-.31.12-.48 0-.55-.45-1-1-1H5.21l-.94-2H1zm16 16c-1.1 0-1.99.9-1.99 2s.89 2 1.99 2 2-.9 2-2-.9-2-2-2z"/></svg>
            Магазин
        </div>
        <div class="nav-item" onclick="switchTab('top', this)">
            <svg viewBox="0 0 24 24"><path d="M19 5h-2V3H7v2H5c-1.1 0-2 .9-2 2v1c0 2.55 1.92 4.63 4.39 4.94.63 1.5 1.98 2.63 3.61 2.96V19H7v2h10v-2h-4v-3.1c1.63-.33 2.98-1.46 3.61-2.96C19.08 12.63 21 10.55 21 8V7c0-1.1-.9-2-2-2zM7 10.82C5.84 10.4 5 9.3 5 8V7h2v3.82zM19 8c0 1.3-.84 2.4-2 2.82V7h2v1z"/></svg>
            Топ
        </div>
        <div class="nav-item" onclick="switchTab('profile', this)">
            <svg viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
            Профиль
        </div>
    </nav>

    <div class="toast-container" id="toast-root"></div>

    <div class="modal-bg" id="modal" onclick="closeModal()">
        <div class="modal-box" onclick="event.stopPropagation()">
            <div class="modal-title" id="m-title">Заголовок</div>
            <div class="modal-body" id="m-body">Текст модалки...</div>
            <div id="m-extra"></div>
            <button class="btn-primary" onclick="closeModal()">ПОНЯТНО</button>
        </div>
    </div>

    <script>
        // Инициализация Telegram SDK
        const tg = window.Telegram.WebApp;
        tg.expand();
        tg.enableClosingConfirmation();

        // База данных Магазина
        const SHOP_DB = [
            { id: 'av_monkey', name: 'NFT Monkey', price: 25, icon: '🐵', desc: 'Уникальный аватар' },
            { id: 'av_robot', name: 'Cyber Bot', price: 50, icon: '🤖', desc: 'Светящийся аватар' },
            { id: 'av_alien', name: 'Alien King', price: 150, icon: '👽', desc: 'Редкий пришелец' },
            { id: 'av_devil', name: 'Hell Lord', price: 300, icon: '😈', desc: 'Премиум статус' }
        ];

        // Состояние приложения (Сохраняется в localStorage)
        let state = {
            user: {
                id: 123456,
                name: "Player",
                ava: "P",
                balance: parseFloat(localStorage.getItem('tb_bal')) || 100.00,
                inv: JSON.parse(localStorage.getItem('tb_inv')) || [],
                history: JSON.parse(localStorage.getItem('tb_hist')) || []
            },
            game: {
                timer: 15,
                poolBlue: 0,
                poolRed: 0,
                isSpinning: false,
                rotation: 0
            }
        };

        // 1. ИНИЦИАЛИЗАЦИЯ
        function initApp() {
            // Берем данные из ТГ, если открыто там
            if (tg.initDataUnsafe?.user) {
                const u = tg.initDataUnsafe.user;
                state.user.id = u.id;
                state.user.name = u.first_name;
                state.user.ava = u.first_name.charAt(0).toUpperCase();
            }
            
            // Обновляем UI Профиля и Шапки
            document.getElementById('hdr-name').innerText = state.user.name;
            document.getElementById('prof-name').innerText = state.user.name;
            document.getElementById('prof-id').innerText = "ID: " + state.user.id;
            
            updateAva(state.user.ava);
            updateBalanceUI();
            
            // Рендер контента
            renderShop();
            renderInv();
            renderHistory();

            // Запуск игрового цикла
            setInterval(gameLoop, 1000);
            
            // Запуск ленты ставок
            setInterval(generateFakeBet, 2500);
        }

        function updateAva(symbol) {
            document.getElementById('hdr-ava').innerText = symbol;
            document.getElementById('prof-ava').innerText = symbol;
        }

        function updateBalanceUI() {
            const b = state.user.balance.toFixed(2);
            document.getElementById('hdr-bal').innerText = b;
            document.getElementById('prof-bal').innerText = b;
            localStorage.setItem('tb_bal', state.user.balance);
        }

        function addHistory(title, amt, type) {
            state.user.history.unshift({ title, amt, type, time: new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) });
            if(state.user.history.length > 20) state.user.history.pop(); // Храним только 20
            localStorage.setItem('tb_hist', JSON.stringify(state.user.history));
            renderHistory();
        }

        // 2. НАВИГАЦИЯ
        function switchTab(tabId, el = null) {
            document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
            if(el) {
                document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
                el.classList.add('active');
            } else {
                // Вызов без клика по меню (например из кода)
                document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
                document.querySelector(`.nav-item[onclick*="${tabId}"]`).classList.add('active');
            }
            document.getElementById('tab-' + tabId).classList.add('active');
        }

        // 3. ИГРОВОЙ ДВИЖОК
        function gameLoop() {
            if (state.game.isSpinning) return;

            state.game.timer--;
            document.getElementById('r-timer').innerText = state.game.timer;

            // Фейковые вливания в пулы для массовости
            if(state.game.timer > 2 && Math.random() > 0.4) {
                let amt = Math.random() * 5;
                if(Math.random() > 0.5) state.game.poolBlue += amt; else state.game.poolRed += amt;
                updatePoolsUI();
            }

            if (state.game.timer <= 0) {
                spinWheel();
            }
        }

        function updatePoolsUI() {
            document.getElementById('pool-blue-val').innerText = state.game.poolBlue.toFixed(2);
            document.getElementById('pool-red-val').innerText = state.game.poolRed.toFixed(2);
            
            let total = state.game.poolBlue + state.game.poolRed;
            if (total > 0) {
                let pBlue = (state.game.poolBlue / total) * 100;
                document.getElementById('bar-blue').style.width = pBlue + '%';
                document.getElementById('bar-red').style.width = (100 - pBlue) + '%';
            } else {
                document.getElementById('bar-blue').style.width = '50%';
                document.getElementById('bar-red').style.width = '50%';
            }
        }

        function spinWheel() {
            state.game.isSpinning = true;
            let wheel = document.getElementById('roulette-wheel');
            
            // Логика вращения (рандомный угол)
            let extra = Math.floor(Math.random() * 360);
            state.game.rotation += (360 * 6) + extra; // 6 полных оборотов + остаток
            
            wheel.style.transform = `rotate(${state.game.rotation}deg)`;

            // Ждем завершения анимации CSS (7 сек)
            setTimeout(() => {
                let finalDeg = state.game.rotation % 360;
                // Синий: 0-180, Красный: 180-360 (грубый подсчет)
                let winner = finalDeg > 180 ? 'RED' : 'BLUE';
                showToast(`Выпал цвет: ${winner} 🎯`, winner === 'RED' ? '#ff3b5c' : '#3b70ff');
                
                setTimeout(resetRound, 3000);
            }, 7500);
        }

        function resetRound() {
            state.game.timer = 15;
            state.game.poolBlue = 0;
            state.game.poolRed = 0;
            state.game.isSpinning = false;
            updatePoolsUI();
        }

        // 4. СТАВКИ
        function setBet(val) {
            let input = document.getElementById('bet-amt');
            if (val === 'max') input.value = state.user.balance.toFixed(2);
            else input.value = parseFloat(val).toFixed(2);
        }

        function adjBet(val) {
            let input = document.getElementById('bet-amt');
            let curr = parseFloat(input.value) || 0;
            if (curr + val > 0) input.value = (curr + val).toFixed(2);
        }

        function placeBet(color) {
            if (state.game.isSpinning) return showToast("Ставки закрыты! 🚫");
            
            let amt = parseFloat(document.getElementById('bet-amt').value);
            if (isNaN(amt) || amt <= 0) return showToast("Некорректная сумма");
            if (amt > state.user.balance) return showToast("Недостаточно TON 💰");

            // Списываем баланс
            state.user.balance -= amt;
            updateBalanceUI();
            
            // Добавляем в пул
            if(color === 'blue') state.game.poolBlue += amt;
            else state.game.poolRed += amt;
            updatePoolsUI();

            addHistory(`Ставка ${color.toUpperCase()}`, amt, 'minus');
            showToast(`Ставка ${amt} TON принята! ✅`);
        }

        function generateFakeBet() {
            if(state.game.isSpinning) return;
            const names = ["Alex", "Doge", "Whale", "TonFan", "Crypto", "Meme"];
            const isBlue = Math.random() > 0.5;
            const amt = (Math.random() * 10 + 1).toFixed(1);
            
            const feed = document.getElementById('live-feed-list');
            const el = document.createElement('div');
            el.className = 'feed-item';
            el.innerHTML = `
                <div class="feed-user">
                    <div class="feed-ava">${names[Math.floor(Math.random()*names.length)][0]}</div>
                    ${names[Math.floor(Math.random()*names.length)]}
                </div>
                <div class="feed-amt ${isBlue ? 'blue' : 'red'}">${amt} TON</div>
            `;
            feed.prepend(el);
            if(feed.children.length > 4) feed.removeChild(feed.lastChild);
        }

        // 5. МАГАЗИН И ИНВЕНТАРЬ
        function renderShop() {
            let html = "";
            SHOP_DB.forEach(item => {
                let isOwned = state.user.inv.includes(item.id);
                html += `
                    <div class="shop-item ${isOwned ? 'item-owned' : ''}">
                        <div class="item-icon">${item.icon}</div>
                        <div class="item-name">${item.name}</div>
                        <div class="item-desc">${item.desc}</div>
                        <div class="item-price">${item.price} TON</div>
                        <button class="btn-buy" onclick="buyItem('${item.id}')">
                            ${isOwned ? 'УЖЕ КУПЛЕНО' : 'КУПИТЬ'}
                        </button>
                    </div>
                `;
            });
            document.getElementById('shop-grid').innerHTML = html;
        }

        function buyItem(id) {
            if(state.user.inv.includes(id)) return showToast("Уже есть в инвентаре!");
            
            let item = SHOP_DB.find(i => i.id === id);
            if(state.user.balance < item.price) return showToast("Не хватает TON 😔");

            // Покупка
            state.user.balance -= item.price;
            state.user.inv.push(id);
            updateBalanceUI();
            
            localStorage.setItem('tb_inv', JSON.stringify(state.user.inv));
            addHistory(`Покупка: ${item.name}`, item.price, 'minus');
            
            showToast(`Успешно куплено: ${item.name} 🎉`);
            renderShop();
            renderInv();
        }

        function renderInv() {
            let html = "";
            // Сначала рисуем купленные предметы
            state.user.inv.forEach(id => {
                let item = SHOP_DB.find(i => i.id === id);
                if(item) {
                    html += `
                        <div class="inv-slot" onclick="equipAva('${item.icon}')" style="cursor:pointer; background:rgba(0,136,204,0.1); border-color:var(--accent);">
                            ${item.icon}
                            <div class="inv-badge">USE</div>
                        </div>
                    `;
                }
            });
            
            // Дополняем пустыми слотами до 8
            let emptySlots = 8 - state.user.inv.length;
            for(let i=0; i<emptySlots; i++) {
                html += `<div class="inv-slot empty"></div>`;
            }
            document.getElementById('inv-grid').innerHTML = html;
        }

        function equipAva(icon) {
            updateAva(icon);
            showToast("Аватар установлен!");
        }

        // 6. ПРОФИЛЬ (История, Промо)
        function renderHistory() {
            let html = "";
            if(state.user.history.length === 0) {
                html = "<div style='padding: 20px; text-align:center; color: var(--text-muted);'>Пусто</div>";
            } else {
                state.user.history.forEach(h => {
                    html += `
                        <div class="hist-item">
                            <div class="h-l"><b>${h.title}</b><span>${h.time}</span></div>
                            <div class="h-r ${h.type}">${h.type === 'plus' ? '+' : '-'}${parseFloat(h.amt).toFixed(2)}</div>
                        </div>
                    `;
                });
            }
            document.getElementById('hist-list').innerHTML = html;
        }

        function activatePromo() {
            let val = document.getElementById('promo-input').value.toUpperCase();
            if(val === 'TONVIP') {
                state.user.balance += 50;
                updateBalanceUI();
                addHistory('Промокод TONVIP', 50, 'plus');
                showToast("Промокод активирован! +50 TON 🎁", "var(--green)");
                document.getElementById('promo-input').value = "";
            } else {
                showToast("Неверный код ❌");
            }
        }

        // 7. UI УТИЛИТЫ (Модалки, Тосты)
        function showModal(type) {
            let mTitle = document.getElementById('m-title');
            let mBody = document.getElementById('m-body');
            let mExtra = document.getElementById('m-extra');
            
            if(type === 'deposit') {
                mTitle.innerText = "Пополнение";
                mBody.innerHTML = "Для пополнения отправьте TON на этот адрес. Баланс обновится автоматически.";
                mExtra.innerHTML = `<div style="background:#000; padding:12px; border-radius:12px; font-family:monospace; word-break:break-all; margin-bottom:20px; border:1px solid var(--border); user-select:all;">UQACY...TEST_ADDRESS_...x8A</div>`;
            } else if (type === 'withdraw') {
                mTitle.innerText = "Вывод";
                mBody.innerHTML = `Доступно: <b>${state.user.balance.toFixed(2)} TON</b>`;
                mExtra.innerHTML = `
                    <input type="number" class="modal-input" placeholder="Сумма вывода">
                    <input type="text" class="modal-input" placeholder="Адрес кошелька TON">
                `;
            }

            document.getElementById('modal').classList.add('show');
        }

        function closeModal() {
            document.getElementById('modal').classList.remove('show');
        }

        function showToast(msg, color = '#fff') {
            const root = document.getElementById('toast-root');
            const toast = document.createElement('div');
            toast.className = 'toast';
            toast.innerHTML = `<span style="color:${color}; font-size:16px;">●</span> ${msg}`;
            
            root.prepend(toast);
            
            setTimeout(() => {
                toast.classList.add('hide');
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        }

        // ЗАПУСК
        window.onload = initApp;

    </script>
</body>
</html>

