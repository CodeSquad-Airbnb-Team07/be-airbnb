import React, { useEffect, useState, useCallback } from "react";
import { useLocation } from "react-router-dom";
import axios from "axios";
import "./SearchPage.css"; // CSS 파일 임포트
import SearchBar from "../components/searchBar/SearchBar.jsx"; // SearchBar 컴포넌트 임포트
import useDebounce from "../hooks/useDebounce.js"; // useDebounce 훅 임포트

const SearchPage = () => {
  const location = useLocation();
  const { filters } = location.state;
  const [accommodations, setAccommodations] = useState([]);

  const [currentPosition, setCurrentPosition] = useState({
    latitude: null,
    longitude: null,
  });
  const [mapLevel, setMapLevel] = useState(5); // 지도 레벨 상태 추가

  const debouncedPosition = useDebounce(currentPosition, 500); // 500ms 디바운스 적용

  const fetchFilteredAccommodations = useCallback(
    async (latitude, longitude) => {
      try {
        const response = await axios.get("/api/products/available", {
          params: {
            checkInDate: filters.checkIn,
            checkOutDate: filters.checkOut,
            minPrice: filters.minPrice,
            maxPrice: filters.maxPrice,
            headCount: filters.capacity,
            latitude: latitude,
            longitude: longitude,
            distance: 10,
          },
        });
        setAccommodations(response.data);
      } catch (error) {
        console.error("Failed to fetch filtered accommodations:", error);
      }
    },
    [filters]
  );

  useEffect(() => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const { latitude, longitude } = position.coords;
          setCurrentPosition({ latitude, longitude });
          fetchFilteredAccommodations(latitude, longitude);
        },
        (error) => {
          console.error("Error fetching location:", error);
        }
      );
    }
  }, [fetchFilteredAccommodations]);

  useEffect(() => {
    if (debouncedPosition.latitude && debouncedPosition.longitude) {
      fetchFilteredAccommodations(
        debouncedPosition.latitude,
        debouncedPosition.longitude
      );
    }
  }, [debouncedPosition, fetchFilteredAccommodations]);

  useEffect(() => {
    if (currentPosition.latitude && currentPosition.longitude) {
      const script = document.createElement("script");
      script.src = `https://dapi.kakao.com/v2/maps/sdk.js?appkey=${
        import.meta.env.VITE_KAKAO_MAP_API_KEY
      }&autoload=false&libraries=services,clusterer,drawing`;
      script.async = true;
      document.head.appendChild(script);

      script.onload = () => {
        window.kakao.maps.load(() => {
          const mapContainer = document.getElementById("map");
          const mapOption = {
            center: new window.kakao.maps.LatLng(
              currentPosition.latitude,
              currentPosition.longitude
            ),
            level: mapLevel,
          };
          const map = new window.kakao.maps.Map(mapContainer, mapOption);

          // accommodations.forEach((acc) => {
          //   const markerPosition = new window.kakao.maps.LatLng(
          //     acc.accommodation.latitude,
          //     acc.longitude
          //   );
          //   const marker = new window.kakao.maps.Marker({
          //     position: markerPosition,
          //     title: acc.name,
          //   });
          //   marker.setMap(map);

          //   const overlayContent = document.createElement("div");
          //   overlayContent.className = "customoverlay";
          //   overlayContent.innerHTML = `
          //     <h4>${acc.name}</h4>
          //     <p>${acc.price.toLocaleString()}원</p>
          //   `;

          //   const customOverlay = new window.kakao.maps.CustomOverlay({
          //     position: markerPosition,
          //     content: overlayContent,
          //     yAnchor: 1,
          //   });

          //   customOverlay.setMap(map);
          // });

          window.kakao.maps.event.addListener(map, "dragend", () => {
            const latlng = map.getCenter();
            const latitude = latlng.getLat();
            const longitude = latlng.getLng();
            setCurrentPosition({ latitude, longitude });
          });

          window.kakao.maps.event.addListener(map, "zoom_changed", () => {
            const level = map.getLevel();
            setMapLevel(level); // 현재 지도 레벨을 상태에 저장
          });
        });
      };
      script.onerror = () => {
        console.error("Failed to load Kakao Maps script");
      };

      return () => {
        document.head.removeChild(script);
      };
    }
  }, [currentPosition, accommodations, mapLevel]);

  return (
    <div className="search-page-container">
      <div className="search-bar-wrapper">
        <SearchBar />
      </div>
      <div className="filtered-results">
        <div className="accommodation-list">
          {/* <ul>
            {accommodations.map((acc) => (
              <li key={acc.id} className="accommodation-item">
                <img src={acc.profileImg} alt={acc.name} />
                <div className="accommodation-details">
                  <h3>{acc.name}</h3>
                  <p>{acc.address.fullAddress}</p>
                  <p>최대 인원: {acc.maxHeadCount}명</p>
                  <p>
                    침대: {acc.bedCount}, 침실: {acc.bedroomCount}, 욕실:{" "}
                    {acc.bathroomCount}
                  </p>
                  <p className="accommodation-price">
                    {acc.price.toLocaleString()}원 / 박
                  </p>
                  <div className="accommodation-rating">
                    <span>⭐</span>
                    <span>
                      {acc.averageGrade} ({acc.reviewCount} 리뷰)
                    </span>
                  </div>
                </div>
              </li>
            ))}
          </ul> */}
        </div>
        <div className="map-container">
          {currentPosition.latitude && currentPosition.longitude ? (
            <div id="map" style={{ width: "100%", height: "100%" }}></div>
          ) : (
            <p>현재 위치를 가져오는 중...</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default SearchPage;