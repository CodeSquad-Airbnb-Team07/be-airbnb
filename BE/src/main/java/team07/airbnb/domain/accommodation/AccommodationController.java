package team07.airbnb.domain.accommodation;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import team07.airbnb.domain.accommodation.dto.AccommodationCreateRequest;
import team07.airbnb.domain.accommodation.dto.AccommodationListResponse;
import team07.airbnb.domain.accommodation.entity.AccommodationEntity;

import java.util.List;

@RequestMapping("/accommodation")
@RestController
@RequiredArgsConstructor
public class AccommodationController {
    private final AccommodationService accommodationService;


    @GetMapping
    public List<AccommodationEntity> findAll() {
        return accommodationService.findAllAccommodations();
    }

    @GetMapping("/location")
    public List<AccommodationListResponse> findNeighbor(
            @RequestParam double longitude,
            @RequestParam double latitude,
            @RequestParam double distance) {

        return accommodationService.findNearbyAccommodations(longitude, latitude, distance)
                .stream()
                .map(AccommodationListResponse::of)
                .toList();
    }

    @PostMapping
    public void createAccomodation(@RequestBody AccommodationCreateRequest createRequest) {

    }

    /**
     * 호스팅할 숙소 유형을 선택하세요. v
     * 숙소 건물 유형을 자세히 설명하세요. ?
     * 게스트가 숙소 공간을 단독으로 사용하는지 명확히 알려주세요. v
     * 숙소 위치를 입력해 주세요. v
     * 숙박 가능한 인원수를 결정하세요. v
     * 숙소 편의시설을 등록하세요.
     * 사진을 추가하고 정리하세요. v
     * 숙소 이름을 정하세요. v
     * 숙소 설명을 작성하세요. v
     * 1박당 요금을 설정하세요.
     */
}
