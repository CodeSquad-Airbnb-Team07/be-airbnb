package team07.airbnb.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import team07.airbnb.common.auth.aop.Authenticated;
import team07.airbnb.data.accommodation.dto.request.AccommodationCreateRequest;
import team07.airbnb.data.accommodation.dto.response.AccommodationDetailResponse;
import team07.airbnb.data.accommodation.dto.response.AccommodationListResponse;
import team07.airbnb.data.product.dto.response.SimpleProductResponse;
import team07.airbnb.data.user.dto.response.TokenUserInfo;
import team07.airbnb.data.user.enums.Role;
import team07.airbnb.entity.AccommodationEntity;
import team07.airbnb.service.accommodation.AccommodationService;
import team07.airbnb.service.product.ProductService;
import team07.airbnb.service.user.UserService;

import java.time.LocalDate;
import java.util.List;

@Tag(name = "숙소")
@RequestMapping("/accommodation")
@RestController
@RequiredArgsConstructor
public class AccommodationController {
    private final AccommodationService accommodationService;
    private final ProductService productService;
    private final UserService userService;

    @Operation(summary = "숙소 등록", description = "스쿼드비엔비에 숙소를 등록합니다.")
    @PostMapping
    @Authenticated(Role.USER)
    public AccommodationListResponse createAccommodation(@RequestBody AccommodationCreateRequest createRequest, TokenUserInfo user) {
        return AccommodationListResponse.of(accommodationService.addAccommodation(
                createRequest.toEntity(userService.getCompleteUser(user))
        ));
    }

    @Operation(summary = "숙소 삭제", description = "등록한 숙소를 삭제합니다.")
    @DeleteMapping("/{id}")
    @Authenticated(Role.HOST)
    public void deleteAccommodation(@PathVariable long id, TokenUserInfo user) {
        accommodationService.deleteById(id, userService.getCompleteUser(user));
    }

    @Operation(summary = "모든 숙소 조회", description = "스쿼드비엔비에 등록된 모든 숙소를 조회합니다.")
    @GetMapping
    public List<AccommodationListResponse> findAll() {
        return previewOf(accommodationService.findAllAccommodations());
    }

    @Operation(summary = "주변 숙소 조회", description = "지정한 위치로부터 지정한 반경 내의 숙소를 조회합니다.")
    @GetMapping("/location")
    public List<AccommodationListResponse> findNeighbor(
            @RequestParam double longitude,
            @RequestParam double latitude,
            @RequestParam double distance) {

        return previewOf(accommodationService.findNearbyAccommodations(longitude, latitude, distance * 1000));
    }

    @Operation(summary = "숙소 상세 조회", description = "숙소의 상세 정보를 조회합니다.")
    @GetMapping("/{id}")
    public AccommodationDetailResponse accommodationDetail(@PathVariable long id) {
        return AccommodationDetailResponse.of(accommodationService.findById(id));
    }

    @Operation(summary = "예약 가능 일자 조회" , description = "지정 년월 중 숙소의 예약 가능 일자와 가격을 조회합니다.")
    @GetMapping("/available/{id}/{date}")
    public List<SimpleProductResponse> availableProducts(@PathVariable LocalDate date, @PathVariable Long id){
        return accommodationService.findAvailableProductsInMonth(date , id)
                .stream()
                .map(SimpleProductResponse::of)
                .toList();
    }


    private List<AccommodationListResponse> previewOf(List<AccommodationEntity> accommodations){
        return accommodations.stream().map(AccommodationListResponse::of).toList();
    }
}
