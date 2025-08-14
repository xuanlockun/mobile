const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const path = require('path');

const setupRestaurantModule = (app, SECRET_KEY, io) => {
  const restaurantRouter = express.Router();

  const db = new sqlite3.Database('./restaurant.db');

  const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

    if (!token) return res.status(401).json({ error: 'Access token missing' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) return res.status(403).json({ error: 'Invalid or expired token' });

      const usersDb = new sqlite3.Database('./users.db');
      usersDb.get('SELECT position FROM users WHERE id = ?', [user.id], (dbErr, userData) => {
        usersDb.close();

        if (dbErr || !userData) {
          return res.status(403).json({ error: 'User not found' });
        }

        if (['Quản Lý', 'Đầu Bếp', 'Phục vụ', 'Nhân viên kho'].includes(userData.position)) {
          req.user = user;
          req.userPosition = userData.position;
          next();
        } else {
          return res.status(403).json({ error: 'Unauthorized position' });
        }
      });
    });
  };

  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS ban (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ten_ban TEXT UNIQUE,
      trang_thai TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS mon_an (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ten_mon TEXT UNIQUE,
      anh TEXT,
      gia INTEGER,
      discount REAL DEFAULT 1
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS kho (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ten_nguyen_lieu TEXT UNIQUE,
      so_luong INTEGER
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS cong_thuc (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mon_id INTEGER,
      nguyen_lieu TEXT,
      so_luong INTEGER,
      FOREIGN KEY (mon_id) REFERENCES mon_an(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS hang_doi (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ten_ban TEXT,
      ten_mon TEXT,
      so_luong INTEGER,
      thoi_gian_dat DATETIME DEFAULT CURRENT_TIMESTAMP,
      trang_thai TEXT DEFAULT 'chờ nấu'
    )`);
  });
  db.run(`CREATE TABLE IF NOT EXISTS hoa_don (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ma_hoa_don TEXT UNIQUE,
      ten_ban TEXT,
      tong_tien INTEGER,
      thoi_gian_thanh_toan DATETIME DEFAULT CURRENT_TIMESTAMP,
      nhan_vien_thanh_toan TEXT,
      ghi_chu TEXT
    )`);

  db.run(`CREATE TABLE IF NOT EXISTS chi_tiet_hoa_don (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hoa_don_id INTEGER,
      ten_mon TEXT,
      so_luong INTEGER,
      gia_ban INTEGER,
      thanh_tien INTEGER,
      FOREIGN KEY (hoa_don_id) REFERENCES hoa_don(id)
    )`);
  db.run(`CREATE TABLE IF NOT EXISTS thong_ke_ngay (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ngay DATE UNIQUE,
      so_hoa_don INTEGER DEFAULT 0,
      tong_doanh_thu INTEGER DEFAULT 0,
      so_khach INTEGER DEFAULT 0,
      cap_nhat_cuoi DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

  db.run(`CREATE TABLE IF NOT EXISTS thong_ke_mon_an (
      id INTEGER,
      ngay DATE,
      ten_mon TEXT,
      so_luong_ban INTEGER DEFAULT 0,
      doanh_thu INTEGER DEFAULT 0,
      PRIMARY KEY (ngay, ten_mon)
    ) WITHOUT ROWID`);
  // ===== Setup Socket.io =====
  io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    db.all(`SELECT * FROM ban`, (err, rows) => {
      if (err) {
        console.error('Error fetching tables:', err);
        return;
      }
      socket.emit('init_status', rows);
    });

    // Gửi hàng đợi hiện tại testing nha
    db.all(`SELECT * FROM hang_doi ORDER BY thoi_gian_dat ASC`, (err, rows) => {
      if (err) {
        console.error('Error fetching queue:', err);
        return;
      }
      socket.emit('update_queue', rows);
    });

    updateKhoAllClients();

    socket.on('disconnect', () => {
      console.log('Client disconnected:', socket.id);
    });
  });

  // ===== Helper Functions =====

  const updateKhoAllClients = () => {
    if (!io) return;
    db.all(`SELECT * FROM kho`, (err, rows) => {
      if (err) {
        console.error('Error fetching inventory:', err);
        return;
      }
      io.emit('update_kho', rows);
    });
  };

  const updateOrderQueueAllClients = () => {
    if (!io) return;
    db.all(`SELECT * FROM hang_doi ORDER BY thoi_gian_dat ASC`, (err, rows) => {
      if (err) {
        console.error('Error fetching queue:', err);
        return;
      }
      io.emit('update_queue', rows);
    });
  };

  // ===== Routes =====

  const capNhatThongKe = (ngay, soHoaDon = 0, tongDoanhThu = 0, soKhach = 0) => {
    db.run(`
      INSERT OR REPLACE INTO thong_ke_ngay (ngay, so_hoa_don, tong_doanh_thu, so_khach, cap_nhat_cuoi)
      VALUES (
        ?,
        COALESCE((SELECT so_hoa_don FROM thong_ke_ngay WHERE ngay = ?), 0) + ?,
        COALESCE((SELECT tong_doanh_thu FROM thong_ke_ngay WHERE ngay = ?), 0) + ?,
        COALESCE((SELECT so_khach FROM thong_ke_ngay WHERE ngay = ?), 0) + ?,
        CURRENT_TIMESTAMP
      )
    `, [ngay, ngay, soHoaDon, ngay, tongDoanhThu, ngay, soKhach]);
  };

  const capNhatThongKeMonAn = (ngay, tenMon, soLuong, doanhThu) => {
    db.run(`
      INSERT OR REPLACE INTO thong_ke_mon_an (ngay, ten_mon, so_luong_ban, doanh_thu)
      VALUES (
        ?, ?,
        COALESCE((SELECT so_luong_ban FROM thong_ke_mon_an WHERE ngay = ? AND ten_mon = ?), 0) + ?,
        COALESCE((SELECT doanh_thu FROM thong_ke_mon_an WHERE ngay = ? AND ten_mon = ?), 0) + ?
      )
    `, [ngay, tenMon, ngay, tenMon, soLuong, ngay, tenMon, doanhThu]);
  };

  // ===== ROUTES =====
  restaurantRouter.post('/mon-an/update-discount', (req, res) => {
    // if (req.userPosition !== 'Quản Lý') {
    //   return res.status(403).json({ error: 'Chỉ quản lý mới có quyền cập nhật giảm giá' });
    // }

    const { ten_mon, discount } = req.body;

    if (!ten_mon || typeof discount !== 'number' || discount <= 0 || discount > 1) {
      return res.status(400).json({ error: 'Thông tin không hợp lệ. Discount phải là số trong khoảng (0, 1]' });
    }

    db.run(`UPDATE mon_an SET discount = ? WHERE ten_mon = ?`, [discount, ten_mon], function (err) {
      if (err) return res.status(500).json({ error: err.message });

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Không tìm thấy món ăn' });
      }

      res.json({ message: `Đã cập nhật discount cho món "${ten_mon}" thành ${discount}` });
    });
  });

  restaurantRouter.get('/mon-an-co-the-nau', (req, res) => {
    db.all(`SELECT * FROM mon_an`, (err, monAnList) => {
      if (err) return res.status(500).send(err.toString());

      db.all(`SELECT * FROM kho`, (err, khoList) => {
        if (err) return res.status(500).send(err.toString());

        const khoMap = {};
        khoList.forEach(k => khoMap[k.ten_nguyen_lieu] = k.so_luong);

        const promises = monAnList.map(mon => {
          return new Promise((resolve) => {
            db.all(`SELECT * FROM cong_thuc WHERE mon_id = ?`, [mon.id], (err, congThuc) => {
              if (err || congThuc.length === 0) return resolve(null);

              // Tính số phần có thể nấu được
              let maxSoLuong = Infinity; // test thử max

              for (let item of congThuc) {
                const slTrongKho = khoMap[item.nguyen_lieu] || 0;
                const soLuongNauDuoc = Math.floor(slTrongKho / item.so_luong);

                if (soLuongNauDuoc <= 0) {
                  maxSoLuong = 0;
                  break;
                }

                if (soLuongNauDuoc < maxSoLuong) {
                  maxSoLuong = soLuongNauDuoc;
                }
              }

              if (maxSoLuong > 0) {
                resolve({
                  ...mon,
                  so_luong_co_the_nau: maxSoLuong
                });
              } else {
                resolve(null);
              }
            });
          });
        });

        Promise.all(promises).then(results => {
          const monAnCoTheNau = results.filter(Boolean);
          res.json(monAnCoTheNau);
        });
      });
    });
  });

  // Thanh toán với lưu lịch sử
  restaurantRouter.post('/thanh-toan', authenticateToken, (req, res) => {
    if (!['Quản Lý', 'Thu Ngân'].includes(req.userPosition)) {
      return res.status(403).json({ error: 'Bạn không có quyền thanh toán' });
    }

    const { ten_ban } = req.body;
    const ngayHienTai = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    const maHoaDon = `HD${Date.now()}`; // Mã hóa đơn duy nhất

    db.all(`
    SELECT hd.ten_mon, hd.so_luong, ma.gia, ma.discount, (hd.so_luong * ma.gia * ma.discount) as thanh_tien
    FROM hang_doi hd
    JOIN mon_an ma ON hd.ten_mon = ma.ten_mon
    WHERE hd.ten_ban = ? AND hd.trang_thai = 'đã nấu xong'
  `, [ten_ban], (err, danhSachMon) => {
      if (err) return res.status(500).send(err.toString());
      if (danhSachMon.length === 0) {
        return res.status(400).send('Không có món nào để thanh toán');
      }

      const tongTien = danhSachMon.reduce((sum, mon) => sum + mon.thanh_tien, 0);

      db.serialize(() => {
        db.run(`
        INSERT INTO hoa_don (ma_hoa_don, ten_ban, tong_tien, nhan_vien_thanh_toan)
        VALUES (?, ?, ?, ?)
      `, [maHoaDon, ten_ban, tongTien, req.user.username], function (err) {
          if (err) return res.status(500).send(err.toString());

          const hoaDonId = this.lastID;

          danhSachMon.forEach(mon => {
            db.run(`
            INSERT INTO chi_tiet_hoa_don (hoa_don_id, ten_mon, so_luong, gia_ban, thanh_tien)
            VALUES (?, ?, ?, ?, ?)
          `, [hoaDonId, mon.ten_mon, mon.so_luong, mon.gia, mon.thanh_tien]);

            capNhatThongKeMonAn(ngayHienTai, mon.ten_mon, mon.so_luong, mon.thanh_tien);
          });

          capNhatThongKe(ngayHienTai, 1, tongTien, 1);

          db.run(`UPDATE ban SET trang_thai = 'trống' WHERE ten_ban = ?`, [ten_ban]);
          db.run(`UPDATE hang_doi SET trang_thai = 'đã thanh toán' WHERE ten_ban = ? AND trang_thai = 'đã nấu xong'`, [ten_ban]);

          if (io) {
            io.emit('update_status', { ten_ban, trang_thai: 'trống' });
            updateOrderQueueAllClients();
          }

          res.json({
            message: `Thanh toán thành công bàn ${ten_ban}`,
            ma_hoa_don: maHoaDon,
            tong_tien: tongTien,
            chi_tiet: danhSachMon
          });
        });
      });
    });
  });

  // Thống kê doanh thu theo ngày
  restaurantRouter.get('/thong-ke/doanh-thu', authenticateToken, (req, res) => {
    if (!['Quản Lý'].includes(req.userPosition)) {
      return res.status(403).json({ error: 'Bạn không có quyền xem thống kê' });
    }

    const { tu_ngay, den_ngay } = req.query;
    let query = `SELECT * FROM thong_ke_ngay`;
    let params = [];

    if (tu_ngay && den_ngay) {
      query += ` WHERE ngay BETWEEN ? AND ?`;
      params = [tu_ngay, den_ngay];
    } else if (tu_ngay) {
      query += ` WHERE ngay >= ?`;
      params = [tu_ngay];
    } else if (den_ngay) {
      query += ` WHERE ngay <= ?`;
      params = [den_ngay];
    }

    query += ` ORDER BY ngay DESC`;

    db.all(query, params, (err, rows) => {
      if (err) return res.status(500).send(err.toString());
      res.json(rows);
    });
  });
  restaurantRouter.post('/mon-an/them-moi', authenticateToken, (req, res) => {
    if (!['Quản Lý', 'Đầu Bếp'].includes(req.userPosition)) {
      return res.status(403).json({ error: 'Bạn không có quyền thêm món mới' });
    }

    const { ten_mon, gia, anh, cong_thuc } = req.body;

    // Validate input
    if (!ten_mon || !gia || gia <= 0) {
      return res.status(400).json({ error: 'Tên món và giá phải được cung cấp và giá phải lớn hơn 0' });
    }

    if (!Array.isArray(cong_thuc) || cong_thuc.length === 0) {
      return res.status(400).json({ error: 'Công thức phải được cung cấp và không được rỗng' });
    }

    // Validate công thức
    for (let item of cong_thuc) {
      if (!item.nguyen_lieu || !item.so_luong || item.so_luong <= 0) {
        return res.status(400).json({ error: 'Mỗi nguyên liệu trong công thức phải có tên và số lượng hợp lệ' });
      }
    }

    db.serialize(() => {
      // Kiểm tra xem món đã tồn tại chưa
      db.get(`SELECT id FROM mon_an WHERE ten_mon = ?`, [ten_mon], (err, existingDish) => {
        if (err) return res.status(500).json({ error: err.message });

        if (existingDish) {
          return res.status(409).json({ error: 'Món ăn đã tồn tại' });
        }

        // Kiểm tra tất cả nguyên liệu có tồn tại trong kho không
        const checkIngredients = cong_thuc.map(item =>
          new Promise((resolve, reject) => {
            db.get(`SELECT ten_nguyen_lieu FROM kho WHERE ten_nguyen_lieu = ?`, [item.nguyen_lieu], (err, khoItem) => {
              if (err) return reject(err);
              if (!khoItem) return reject(`Nguyên liệu "${item.nguyen_lieu}" không tồn tại trong kho`);
              resolve();
            });
          })
        );

        Promise.all(checkIngredients)
          .then(() => {
            // Thêm món mới vào database
            db.run(
              `INSERT INTO mon_an (ten_mon, gia, anh, discount) VALUES (?, ?, ?, 1)`,
              [ten_mon, gia, anh || null],
              function (err) {
                if (err) return res.status(500).json({ error: err.message });

                const mon_id = this.lastID;

                // Thêm công thức
                const insertRecipes = cong_thuc.map(item =>
                  new Promise((resolve, reject) => {
                    db.run(
                      `INSERT INTO cong_thuc (mon_id, nguyen_lieu, so_luong) VALUES (?, ?, ?)`,
                      [mon_id, item.nguyen_lieu, item.so_luong],
                      (err) => {
                        if (err) return reject(err);
                        resolve();
                      }
                    );
                  })
                );

                Promise.all(insertRecipes)
                  .then(() => {
                    res.json({
                      message: `Đã thêm món "${ten_mon}" thành công`,
                      mon_id: mon_id,
                      ten_mon: ten_mon,
                      gia: gia,
                      cong_thuc: cong_thuc
                    });
                  })
                  .catch(err => {
                    // Rollback: xóa món vừa thêm nếu thêm công thức thất bại
                    db.run(`DELETE FROM mon_an WHERE id = ?`, [mon_id]);
                    res.status(500).json({ error: 'Lỗi khi thêm công thức: ' + err.message });
                  });
              }
            );
          })
          .catch(err => {
            res.status(400).json({ error: err });
          });
      });
    });
  });

  // Lấy danh sách nguyên liệu trong kho
  restaurantRouter.get('/kho/nguyen-lieu', authenticateToken, (req, res) => {
    db.all(`SELECT ten_nguyen_lieu, so_luong FROM kho ORDER BY ten_nguyen_lieu`, (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  // Lấy công thức của một món
  restaurantRouter.get('/mon-an/:id/cong-thuc', authenticateToken, (req, res) => {
    const { id } = req.params;

    db.all(`
    SELECT ct.nguyen_lieu, ct.so_luong, k.so_luong as ton_kho
    FROM cong_thuc ct
    LEFT JOIN kho k ON ct.nguyen_lieu = k.ten_nguyen_lieu
    WHERE ct.mon_id = ?
    ORDER BY ct.nguyen_lieu
  `, [id], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });
  // Thống kê món ăn bán chạy best saller á
  restaurantRouter.get('/thong-ke/mon-ban-chay', authenticateToken, (req, res) => {
    if (!['Quản Lý', 'Đầu Bếp'].includes(req.userPosition)) {
      return res.status(403).json({ error: 'Bạn không có quyền xem thống kê' });
    }

    const { tu_ngay, den_ngay, limit = 10 } = req.query;
    let query = `
      SELECT ten_mon, 
             SUM(so_luong_ban) as tong_so_luong,
             SUM(doanh_thu) as tong_doanh_thu,
             AVG(doanh_thu/so_luong_ban) as gia_trung_binh
      FROM thong_ke_mon_an
    `;
    let params = [];

    if (tu_ngay && den_ngay) {
      query += ` WHERE ngay BETWEEN ? AND ?`;
      params = [tu_ngay, den_ngay];
    } else if (tu_ngay) {
      query += ` WHERE ngay >= ?`;
      params = [tu_ngay];
    } else if (den_ngay) {
      query += ` WHERE ngay <= ?`;
      params = [den_ngay];
    }

    query += ` GROUP BY ten_mon ORDER BY tong_so_luong DESC LIMIT ?`;
    params.push(parseInt(limit));

    db.all(query, params, (err, rows) => {
      if (err) return res.status(500).send(err.toString());
      res.json(rows);
    });
  });

  // Thống kê doanh thu hôm nay
  restaurantRouter.get('/thong-ke/hom-nay', authenticateToken, (req, res) => {
    const ngayHienTai = new Date().toISOString().split('T')[0];

    db.get(`SELECT * FROM thong_ke_ngay WHERE ngay = ?`, [ngayHienTai], (err, thongKeNgay) => {
      if (err) return res.status(500).send(err.toString());

      db.all(`
        SELECT ten_mon, so_luong_ban, doanh_thu 
        FROM thong_ke_mon_an 
        WHERE ngay = ? 
        ORDER BY so_luong_ban DESC
      `, [ngayHienTai], (err, thongKeMonAn) => {
        if (err) return res.status(500).send(err.toString());

        res.json({
          ngay: ngayHienTai,
          tong_quan: thongKeNgay || { so_hoa_don: 0, tong_doanh_thu: 0, so_khach: 0 },
          mon_an_ban_chay: thongKeMonAn
        });
      });
    });
  });

  // Lấy lịch sử hóa đơn
  restaurantRouter.get('/hoa-don/lich-su', authenticateToken, (req, res) => {
    if (!['Quản Lý', 'Thu Ngân'].includes(req.userPosition)) {
      return res.status(403).json({ error: 'Bạn không có quyền xem lịch sử hóa đơn' });
    }

    const { tu_ngay, den_ngay, limit = 50 } = req.query;
    let query = `
      SELECT hd.*, 
             GROUP_CONCAT(cthd.ten_mon || ' x' || cthd.so_luong) as chi_tiet_mon
      FROM hoa_don hd
      LEFT JOIN chi_tiet_hoa_don cthd ON hd.id = cthd.hoa_don_id
    `;
    let params = [];

    if (tu_ngay && den_ngay) {
      query += ` WHERE DATE(hd.thoi_gian_thanh_toan) BETWEEN ? AND ?`;
      params = [tu_ngay, den_ngay];
    }

    query += ` GROUP BY hd.id ORDER BY hd.thoi_gian_thanh_toan DESC LIMIT ?`;
    params.push(parseInt(limit));

    db.all(query, params, (err, rows) => {
      if (err) return res.status(500).send(err.toString());
      res.json(rows);
    });
  });
  // Initialize data
  restaurantRouter.get('/init', authenticateToken, (req, res) => {
    if (req.userPosition !== 'Quản Lý') {
      return res.status(403).json({ error: 'Bạn không có quyền khởi tạo dữ liệu' });
    }

    db.serialize(() => {
      for (let i = 1; i <= 10; i++) {
        db.run(`INSERT OR IGNORE INTO ban (ten_ban, trang_thai) VALUES (?, 'trống')`, [`Bàn ${i}`]);
      }

      db.run(`INSERT OR IGNORE INTO mon_an (ten_mon, gia, discount) VALUES 
        ('Phở', 50000, 1),
        ('Bún bò', 60000, 1),
        ('Cơm tấm', 45000, 1),
        ('Mì Quảng', 55000, 0.95),
        ('Cháo gà', 40000, 1),
        ('Bánh mì trứng', 30000, 0.9),
        ('Bánh canh', 45000, 1),
        ('Gỏi cuốn', 25000, 0.8),
        ('Cơm gà', 50000, 1),
        ('Bún chả', 55000, 1)
      `);

      db.run(`
        INSERT INTO thong_ke_ngay (ngay, so_hoa_don, tong_doanh_thu, so_khach) VALUES
        ('2025-05-20', 50, 5750000, 50),
        ('2025-05-21', 30, 6420000, 30),
        ('2025-05-22', 60, 4890000, 60),
        ('2025-05-23', 40, 5610000, 40),
        ('2025-05-24', 70, 4980000, 70),
        ('2025-05-25', 20, 6300000, 20),
        ('2025-05-26', 80, 6250000, 80),
        ('2025-05-27', 40, 5560000, 40)
      `);

      db.run(`INSERT OR IGNORE INTO kho (ten_nguyen_lieu, so_luong) VALUES 
        ('bún', 10000), ('thịt bò', 8000), ('cơm', 10000), ('sườn', 5000), ('rau', 3000),
        ('mì quảng', 5000), ('gà', 6000), ('cháo', 4000), ('trứng', 2000), ('bánh mì', 3000),
        ('nước lèo', 8000), ('chả', 3000), ('bún chả', 6000), ('hành', 1500)
      `);

      const insertRecipe = (mon, congThuc) => {
        db.get(`SELECT id FROM mon_an WHERE ten_mon = ?`, [mon], (err, row) => {
          if (err) {
            console.error(`Lỗi khi lấy id của món ${mon}:`, err);
            return;
          }
          if (row) {
            const mon_id = row.id;
            const placeholders = congThuc.map(() => `(?, ?, ?)`).join(', ');
            const values = congThuc.flatMap(([nguyen_lieu, so_luong]) => [mon_id, nguyen_lieu, so_luong]);

            db.run(
              `INSERT OR IGNORE INTO cong_thuc (mon_id, nguyen_lieu, so_luong) VALUES ${placeholders}`,
              values,
              (err) => {
                if (err) console.error(`Lỗi khi chèn công thức cho món ${mon}:`, err);
              }
            );
          }
        });
      };

      // Danh sách công thức theo món
      insertRecipe('Phở', [['bún', 500], ['thịt bò', 300], ['hành', 50]]);
      insertRecipe('Bún bò', [['bún', 600], ['thịt bò', 400], ['rau', 200]]);
      insertRecipe('Cơm tấm', [['cơm', 700], ['sườn', 500], ['rau', 100]]);
      insertRecipe('Mì Quảng', [['mì quảng', 500], ['gà', 400], ['rau', 200]]);
      insertRecipe('Cháo gà', [['cháo', 700], ['gà', 300], ['hành', 50]]);
      insertRecipe('Bánh mì trứng', [['bánh mì', 1], ['trứng', 2], ['rau', 50]]);
      insertRecipe('Bánh canh', [['bánh canh', 600], ['thịt bò', 300], ['nước lèo', 400]]);
      insertRecipe('Gỏi cuốn', [['rau', 200], ['thịt bò', 150], ['bún', 100]]);
      insertRecipe('Cơm gà', [['cơm', 700], ['gà', 400], ['hành', 50]]);
      insertRecipe('Bún chả', [['bún chả', 700], ['chả', 300], ['rau', 150]]);

    });

    setTimeout(() => {
      updateKhoAllClients();
      updateOrderQueueAllClients();
      db.all(`SELECT * FROM ban`, (err, rows) => {
        if (!err) {
          io.emit('init_status', rows);
        }
      });
    }, 1000);

    res.send('Đã khởi tạo bàn, món và kho');
  });

  // Get menu
  // restaurantRouter.get('/mon-an', authenticateToken, (req, res) => {
  //   db.all(`SELECT * FROM mon_an`, (err, rows) => {
  //     res.json(rows);
  //   });
  // });
  restaurantRouter.get('/mon-an', authenticateToken, (req, res) => {
    db.all(`SELECT id, ten_mon, anh, gia, discount, gia * discount AS gia_khuyen_mai FROM mon_an`, (err, rows) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(rows);
    });
  });

  // Get inventory
  restaurantRouter.get('/kho', authenticateToken, (req, res) => {
    if (!['Quản Lý', 'Đầu Bếp'].includes(req.userPosition)) {
      return res.status(403).json({ error: 'Bạn không có quyền xem kho' });
    }

    db.all(`SELECT * FROM kho`, (err, rows) => {
      res.json(rows);
    });
  });

  restaurantRouter.get('/ping2', (req, res) => {
    res.json("ping success");
  });

  // Order food
  restaurantRouter.post('/dat-mon', authenticateToken, (req, res) => {
    const { ten_ban, danh_sach_mon } = req.body;

    if (!ten_ban || !Array.isArray(danh_sach_mon) || danh_sach_mon.length === 0) {
      return res.status(400).send('Thiếu thông tin bàn hoặc danh sách món không hợp lệ');
    }

    db.serialize(() => {
      let errorOccurred = false;
      let remaining = danh_sach_mon.length;

      danh_sach_mon.forEach(({ ten_mon, so_luong }) => {
        if (!ten_mon || !so_luong || so_luong <= 0) {
          errorOccurred = true;
          return res.status(400).send('Tên món hoặc số lượng không hợp lệ');
        }

        db.get(`SELECT id FROM mon_an WHERE ten_mon = ?`, [ten_mon], (err, mon) => {
          if (err || !mon) {
            errorOccurred = true;
            return res.status(404).send(`Món "${ten_mon}" không tồn tại`);
          }

          db.run(
            `INSERT INTO hang_doi (ten_ban, ten_mon, so_luong, trang_thai) VALUES (?, ?, ?, 'chờ nấu')`,
            [ten_ban, ten_mon, so_luong],
            function (err) {
              if (err) {
                errorOccurred = true;
                return res.status(400).send(err.toString());
              }

              remaining--;
              if (remaining === 0 && !errorOccurred) {
                db.run(
                  `UPDATE ban SET trang_thai = 'đã đặt món' WHERE ten_ban = ?`,
                  [ten_ban],
                  () => {
                    if (io) {
                      io.emit('update_status', { ten_ban, trang_thai: 'đã đặt món' });
                      updateOrderQueueAllClients();
                    }
                    res.json({ message: 'Đặt món thành công, đã thêm vào hàng đợi' });
                  }
                );
              }
            }
          );
        });
      });
    });
  });

  restaurantRouter.get('/hang-doi', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM hang_doi ORDER BY thoi_gian_dat ASC`, (err, rows) => {
      if (err) return res.status(500).send(err.toString());
      res.json(rows);
    });
  });

  restaurantRouter.post('/nau-xong', authenticateToken, (req, res) => {
    if (req.userPosition !== 'Đầu Bếp' && req.userPosition !== 'Quản Lý') {
      return res.status(403).json({ error: 'Bạn không có quyền xác nhận nấu xong' });
    }

    const { id } = req.body;

    db.get(`SELECT * FROM hang_doi WHERE id = ?`, [id], (err, order) => {
      if (err || !order) return res.status(404).send('Không tìm thấy đơn hàng');

      db.get(`SELECT id FROM mon_an WHERE ten_mon = ?`, [order.ten_mon], (err, mon) => {
        if (!mon) return res.status(404).send('Món không tồn tại');

        db.all(`SELECT * FROM cong_thuc WHERE mon_id = ?`, [mon.id], (err, congThuc) => {
          if (!congThuc.length) return res.status(404).send('Không có công thức');

          const updates = congThuc.map(ct => new Promise((resolve, reject) => {
            db.get(`SELECT so_luong FROM kho WHERE ten_nguyen_lieu = ?`, [ct.nguyen_lieu], (err, khoRow) => {
              if (!khoRow || khoRow.so_luong < ct.so_luong) {
                return reject(`Không đủ ${ct.nguyen_lieu}`);
              }
              db.run(`UPDATE kho SET so_luong = so_luong - ? WHERE ten_nguyen_lieu = ?`,
                [ct.so_luong, ct.nguyen_lieu], (err) => {
                  if (err) return reject(err);
                  resolve();
                });
            });
          }));

          Promise.all(updates)
            .then(() => {
              db.run(`UPDATE hang_doi SET trang_thai = 'đã nấu xong' WHERE id = ?`, [id], () => {
                db.run(`UPDATE ban SET trang_thai = 'đã phục vụ chưa thanh toán' WHERE ten_ban = ?`,
                  [order.ten_ban], () => {
                    // Emit cập nhật trạng thái mới cho bàn
                    if (io) {
                      io.emit('update_status', {
                        ten_ban: order.ten_ban,
                        trang_thai: 'đã phục vụ chưa thanh toán'
                      });

                      updateKhoAllClients();
                      updateOrderQueueAllClients();
                    }
                    res.send('Đã nấu xong và phục vụ cho khách');
                  });
              });
            })
            .catch(err => {
              res.status(400).send(err.toString());
            });
        });
      });
    });
  });


  // Check table status
  restaurantRouter.get('/trang-thai-ban/:ten_ban', authenticateToken, (req, res) => {
    const { ten_ban } = req.params;

    db.get(`SELECT * FROM ban WHERE ten_ban = ?`, [ten_ban], (err, table) => {
      if (err) return res.status(500).send(err.toString());
      if (!table) return res.status(404).send('Không tìm thấy bàn');

      res.json(table);
    });
  });

  // Get order history for a table
  restaurantRouter.get('/lich-su-dat-mon/:ten_ban', authenticateToken, (req, res) => {
    const { ten_ban } = req.params;

    db.all(`SELECT * FROM hang_doi WHERE ten_ban = ? ORDER BY thoi_gian_dat DESC`,
      [ten_ban], (err, rows) => {
        if (err) return res.status(500).send(err.toString());
        res.json(rows);
      });
  });

  // Get all tables
  restaurantRouter.get('/danh-sach-ban', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM ban`, (err, rows) => {
      if (err) return res.status(500).send(err.toString());
      res.json(rows);
    });
  });

  // Get bill for a table
  restaurantRouter.get('/hoa-don', authenticateToken, (req, res) => {
    const query = `
    SELECT 
      hd.ten_ban, 
      hd.ten_mon, 
      hd.so_luong, 
      ma.gia, 
      ma.discount,
      hd.so_luong * ma.gia * ma.discount AS thanh_tien
    FROM hang_doi hd
    JOIN mon_an ma ON hd.ten_mon = ma.ten_mon
    WHERE hd.trang_thai = 'đã nấu xong'
  `;

    db.all(query, [], (err, rows) => {
      if (err) return res.status(500).send(err.toString());

      const hoaDonMap = {};

      rows.forEach(row => {
        if (!hoaDonMap[row.ten_ban]) {
          hoaDonMap[row.ten_ban] = {
            ten_ban: row.ten_ban,
            danh_sach_mon: [],
            tong_tien: 0,
          };
        }

        hoaDonMap[row.ten_ban].danh_sach_mon.push({
          ten_mon: row.ten_mon,
          so_luong: row.so_luong,
          gia: row.gia,
          discount: row.discount,
          gia_sau_khuyen_mai: row.gia * row.discount,
          thanh_tien: row.thanh_tien,
        });

        hoaDonMap[row.ten_ban].tong_tien += row.thanh_tien;
      });

      const result = Object.values(hoaDonMap);
      res.json(result);
    });
  });


  // Clean up function
  const cleanup = () => {
    db.close();
  };

  return {
    router: restaurantRouter,
    cleanup
  };
};

module.exports = setupRestaurantModule;