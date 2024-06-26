# be-airdnb

마스터즈 2024 BE 프로젝트 숙박앱

## 👫 Team1 소개 👫

|                                    개발(BE)                                     |                                    개발(BE)                                     |
| :-----------------------------------------------------------------------------: | :-----------------------------------------------------------------------------: |
| <img width="160px" src="https://avatars.githubusercontent.com/u/87180146?v=4"/> | <img width="160px" src="https://avatars.githubusercontent.com/u/85686722?v=4"/> |
|                    [@Miensoap](https://github.com/Miensoap)                     |                   [@soyesenna](https://github.com/soyesenna)                    |
|                                      Soap                                       |                                      Senna                                      |

## Notion

[노션 페이지](https://fallacious-cadet-384.notion.site/AirBnB-fd3159ffb3714d4a953011849346278f?pvs=4)

---

## 1주차 PR

##🚀 Pull Request

### 구현 내용

- 주변 숙소 조회 API
- 예약 가능한 주변 상품 조회 API
- 숙소 등록 , 상세 조회, 삭제 API
- 상품 등록 API
- 예약 전 금액 확인 API

---

- 깃허브 , 구글 OAuth 로그인 구현
- 인증 후 JWT 토큰에 담기 현재 유저 정보 사용 가능

### 고민 사항

- Point , LocalDate , LocalDateTime : Serializer Deserializer 오류나서 직접 구현
- 프론트 페이지에서 OAuth 로그인 구현 안되는중 😭😭😭
- 서버 로그를 ec2 접속하지 않고 보고싶어요

### 기타

- github action + docker + ec2 사용해 자동 [배포중](https://squadbnb.site)
- next -> react로 변경

---

## 2주차 PR

---

### 요약

- 예약, 위시리스트 , 리뷰 API
- SpringDoc
- JWT 토큰에 담는 유저 정보 수정
- 패키지 구조 수정

---

### 고민

- 패키지 구조를 도메인별로 사용하고 있었는데, 레이어를 명확히 구분하기 위해 수정 시도중이에요
- 테스트 코드가 필요할 것 같아요
- 수정을 구현할 때 Entity에 setter를 만들어 dirty checking을 사용할지, PUT 으로 모든 정보를 한 번에 수정할지, ... ... ...

## 요약

#### 결정

- 패키지 구조 수정
- Custom Exception 구조화 , GlobalExceptionHadler에서 공통 처리
- Api 공통 응답 객체는 사용하지 않기로 결정
- schema.sql 작성 -> ddl-auto 기능 validate / none 사용
  ![image](https://github.com/codesquad-members-2024/be-airdnb/assets/87180146/ae18776e-076f-41a4-9ed7-b457f9018153)

#### 기능

- 월별 예약 가능 일자 조회 API
- .내가 등록한 숙소 조회
- 내 숙소에 대한 예약 조회
- 내 예약 조회 (유저)
- 예약 단독 상세 조회
- 예약 이용 완료
- 요금 그래프
- 예약 수정
- 댓글 내용 수정
  <br>

## 기타

- config 분리
- allow url Set으로 관리
- validation 일부 적용 , 예외 처리
- 응답 DTO 추가

---

[nginx 이슈](https://github.com/CodeSquad-Airbnb-Team07/be-airbnb/issues/4) 해결!

👉👉 https://squadbnb.site/api/docs
![image](https://github.com/codesquad-members-2024/be-airdnb/assets/87180146/4387d2c0-545e-41e7-b6ee-7d12656acdb0)

---

## 이후 계획

1. **숙소 수정**
2. **리뷰 수정**
3. **결제 진행**
4. **숙소 필터링**
5. **예약 알림**

## 리마인드 😸

- 다음 PR은 세나가 작성
- 다음 주에는 500~800줄 정도로 쪼개서 PR
