import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import mysql from 'mysql2/promise'; // mysql2/promise로 변경
import dotenv from 'dotenv';
import MySQLStore from 'express-mysql-session';
import MySQLStoreFactory from 'express-mysql-session';
import session from 'express-session';
import passport from 'passport';
import passportSocketIo from 'passport.socketio';
import cookieParser from 'cookie-parser';

const sessionTime:number = 3000 * 60 * 60 * 1000;  //세션 유효시간(ms 단위)


dotenv.config();

const app = express();
const port = process.env.PORT || 8080;

app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/* socket.io 설정 */
const { createServer } = require('http')
const { Server } = require('socket.io')
const server = createServer(app)
const io = new Server(server, {
  cors: {
    origin: "http://localhost:8080",
    methods: ["GET", "POST"],
    credentials: true,
  },
});
const { join } = require("node:path");



/* MySQL 연결 설정 */
//pool로 동시 연결성 확장할 수 있다함
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: process.env.SQL_PASS,
  database: 'nodechat',
  waitForConnections: true,
  connectionLimit: 10, // 동시에 사용할 수 있는 최대 연결 수
});

// 세션 스토어 생성
const MySQLStore = MySQLStoreFactory(session);
const sessionStore = new MySQLStore({}, pool);
const sessionMiddleware = session({
  secret: process.env.SQL_PASS,
  resave: true,
  saveUninitialized: true,
  store: sessionStore, // MySQL 세션 스토어 사용
  cookie: { maxAge: sessionTime},
});
app.use(sessionMiddleware);

let connection: mysql.Connection;
async function connectToDatabase() {
  try {
    connection = await pool.getConnection();
    console.log('MySQL 연결된듯');
  } catch (err) {
    console.error('MySQL 연결 안된듯:', err);
    throw err;
  }
}
connectToDatabase();

// async function connectToDatabase() { //단일연결 버전
//   try {
//     connection = await mysql.createConnection({
//       host: 'localhost',
//       user: 'root',
//       password: process.env.SQL_PASS,
//       database: 'nodechat',
//     });
//     console.log('MySQL 연결된듯');
//   } catch (err) {
//     console.error('MySQL 연결 안된듯:', err);
//     throw err;
//   }
// }
//연결

// passport 라이브러리 설정
const LocalStrategy = require('passport-local')

//세션 설정
app.use(session({
  secret: 'test', //암호화 할때 쓸 비번인데
  store:sessionStore, //세션저장
  resave : false,
  saveUninitialized : false,
  cookie : { maxAge : sessionTime}  //ms 단위
}))
app.use(passport.session());
app.use(passport.initialize())

passport.serializeUser((user, done) => {  //세션 쿠키 만들어줌
  process.nextTick(() => {
    done(null, { id: user.id, username: user.username })
  })
})
passport.deserializeUser((user, done) => {  //로그인 할때 쿠키 확인
  process.nextTick(async() => {
    // MySQL에서 사용자 정보 조회 (나중에 닉네임 등등 바꿀 수 있으니 쿠키에 있는 정보 말고 최신정보로 따서 user에 넣어줌)
    const [rows] = await connection.execute('SELECT username, ip, registration_time FROM user WHERE username = ?', [user.username]);
    //console.log(rows);
    // 사용자 정보가 없으면 에러 처리
    if (rows == undefined||rows ==null) {
      return done(new Error('사용자를 찾을 수 없습니다.'));
    }
    // 사용자 정보 객체 생성(필요한것만 추가하기)
    const userInfo = {
      username: rows[0].username,
      registration_time: rows[0].registration_time,
      ip: rows[0].ip,
    };
    return done(null, userInfo)
  })
})

//passport 로그인 작동 부분
passport.use(new LocalStrategy(async (username, 입력한비번, cb) => {  
  try {
    // MySQL에서 사용자 조회
    const [results] = await connection.execute('SELECT * FROM user WHERE username = ?', [username]);
    //console.log(results); 
    if (Array.isArray(results) && results.length <= 0) { //배열 맞는지 검사 && 아이디 검색결과 0개인지 확인
      return cb(null, false, { message: '아이디 DB에 없는데요' });
    }

    const result = results[0];

    // 비밀번호 확인
    if (await bcrypt.compare(입력한비번, result.password)) {  //bcrypt로 비밀번호 확인
      return cb(null, result);
    } else {
      return cb(null, false, { message: '비번트렸어요' });
    }
  } catch (error) {
    console.error('로그인 중 오류 발생:', error);
    return cb(error);
  }
}));

/** 미들웨어 및 함수 */
//로그인이 필요한 페이지에 가져다 쓰는 미들웨어 >로그인 상태면 다음 진행 or 로그아웃 상태일 시 home으로 redirect
function checkLogin(req,res,next){ 
  if(req.isAuthenticated()) {
    return next();
  }
  else{
    res.redirect('/');
  }
}

//username 넣으면 오브젝트로 유저 정보 반환
const getUserInfo:(object) = async (connection, username) => {
  try {
    // SQL 쿼리 실행: 해당 username의 정보를 가져옴 (비밀번호는 제외)
    const [rows] = await connection.execute(
      'SELECT username, ip, registration_time FROM user WHERE username = ?',
      [username]
    );

    // 조회된 유저가 없을 경우
    if (rows.length === 0) {
      return null;
    }

    // 비밀번호를 제외한 유저 정보 반환
    const userInfo = {
      username: rows[0].username,
      ip: rows[0].ip,
      registration_time: rows[0].registration_time,
    };

    return userInfo;
  } catch (error) {
    console.error('Error fetching user info:', error);
    throw error;
  }
};


/* 라우팅 시작 */
server.listen(port, () => {
  console.log('http://localhost:8080 에서 서버 실행중');
});

app.get('/', (req: Request, res: Response) => {

  //이미 로그인 세션이 있다면 chat 페이지로 리다이렉트 
  if(req.isAuthenticated()){
    res.redirect('/chat');
    return;
  }
  res.render('home.ejs');
});

app.post('/login', async (req: Request, res: Response, next) => {
  passport.authenticate('local', (error, user, info) => {
    if (error) return res.status(500).json(error)
    if (!user) return res.status(401).json(info.message)
    req.logIn(user, (err) => {
      if (err) return next(err)
      res.redirect('/chat')
    })
})(req, res, next)
}) 

//로그아웃
app.get('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

//회원가입 페이지
app.get('/register', (req: Request, res: Response) => {
  res.render('register.ejs');
});

//회원가입 post 요청
app.post('/register', async (req: Request, res: Response) => {
  console.log('username/ip: ' + `${req.body.username}/${req.ip}`);
  const { username, password } = req.body;
  const ip = req.ip;
  const time = new Date()
  const registrationTime = time.toISOString().slice(0, 19).replace('T', ' ');

  //유저가 프론트 위조해서 긴 요청 보냈는지 검사
  if(password.length>18||username.length>12){
    res.status(409).json({ message: '그러지 말아주세요' });
    return;
  }

  try {
    // 아이디 중복 확인 (username 있는지 검사)
    const [results]: [any[], any] = await connection.execute('SELECT * FROM user WHERE username = ?', [username]);

    //닉네임 검색 결과 1개 이상 결과가 있다면 중복 아이디이므로 종료
    if (results.length > 0) {
      res.status(409).json({ message: '이미 사용 중인 아이디입니다.' });
      return;
    }

    // 비밀번호 해싱
    const hashedPassword = await bcrypt.hash(password, 10);

    // 최종적으로 user 테이블에 사용자 정보 insert 
    await connection.execute(
      'INSERT INTO user (username, password, ip, registration_time) VALUES (?, ?, ?, ?)', //user 테이블에 삽입
      [username, hashedPassword, ip, registrationTime]
    );

    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).send('서버 오류');
  }
});

app.get('/chat',checkLogin, (req: Request, res: Response) => {
  res.render('chat.ejs',{username:req.user.username});
});


io.engine.use(sessionMiddleware);

// Socket.io와 Passport.js 세션 공유 설정
io.use(passportSocketIo.authorize({
  key: 'connect.sid', // 쿠키 이름 (기본값)
  secret: process.env.SQL_PASS, // 세션 비밀키 (Express와 동일해야 함)
  store: sessionStore, // express-mysql-session 스토어
  success: onAuthorizeSuccess,
  fail: onAuthorizeFail,
}));

function onAuthorizeSuccess(data, accept) {
  //console.log('successful connection to socket.io');
  accept(null, true);
}

function onAuthorizeFail(data, message, error, accept) {
  console.error('소켓 인증 실패:', message);  // 오류 메시지 출력
  if (error) accept(new Error(message));
}

let connectUsers =[];

//소켓 연결!
io.on('connection', async(socket) => {
  // 현재 접속한 유저 정보 확인
  const user = socket.request.user; // passport-socketio로부터 유저 정보 qkedkdha

  const username = user.username;
  const registerDate = user.registration_time
  const nickname = user.nickname || null; //필요할지도?

  console.log(`${user.registration_time} - websocket 연결됨`);

  socket.join(username);  //모든 유저는 자신의 id로 된 room에 일단 join시켜둠
  io.emit('userJoin',{username:username,registerDate:registerDate});  //그리고 내가 왔다고 알림

  //기존 connectUsers를 새로운 유저(나)에게만 전송
  io.to(username).emit('existingUsers', connectUsers);

  //(새로운 유저)(나)를 connectUsers에 추가
  connectUsers.push({ username, registerDate });
  console.log(connectUsers);

  /**
   * 특정 유저 한명에게만 통신 전달하는 함수(1:1채팅방에서 추가할 수 있는 다양한 이벤트 처리하기 용이할 것 같아 함수화)
   * 
   * @param {string} to - 메시지 받을 유저의 소켓 ID
   * @param {string} from - 메시지 보낸 유저의 소켓 ID(현재까지는 username과 개인 소켓 이름 일치하지만 수정시 수정해야 함)
   * @param {string} event - 이벤트 유형
   * @param {string} message - 전달할 메시지 내용
 */
  function sendMessageByUsername(to,from,event,message){
    io.to(to).emit('privateMessage',{event:event,message:message,from:from});
  }

  //공개 메시지 수신 > 모든 유저에게 emit
  socket.on('publicMessage',(data)=>{
    //console.log('단체메시지 수신됨'+data);
    io.emit('publicMessage',{username:data.username,message:data.message});
  })

  //개인 메시지 수신 > 목표 사용자에게만 emit
  socket.on('privateMessage',async (data)=>{
    const receivingUser : string = data.receivingUser;
    const sentUser :string = username; 
    const message : string = data.message;
    const event : string = data.event

    console.log(`개인메시지: ${receivingUser}에게 ${sentUser}가 ${message}/`);
    sendMessageByUsername(receivingUser,sentUser,event,message);
  })

  //유저 연결 끊어짐 수신 > 모든 유저에게 emit
  socket.on('disconnect', () => {
    
    // connectUsers에서 해당 유저를 제거
    connectUsers = connectUsers.filter(user => user.username !== username);
    console.log(connectUsers.length);

    console.log(`${user.username} 퇴장.`);
    io.emit('userLeft',user.username); //퇴장한 username 전파
  });
})