package team07.airbnb.domain.accommodation;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import team07.airbnb.domain.accommodation.dto.AccommodationCreateRequest;
import team07.airbnb.domain.accommodation.dto.AccommodationListResponse;
import team07.airbnb.domain.accommodation.entity.AccommodationEntity;
import team07.airbnb.domain.user.entity.UserEntity;
import team07.airbnb.domain.user.service.UserService;

import java.util.List;

@RequestMapping("/accommodation")
@RestController
@RequiredArgsConstructor
public class AccommodationController {
    private final AccommodationService accommodationService;
    private final UserService userService;


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
        UserEntity host = userService.findAnyUser();
        accommodationService.addAccommodation(
                createRequest.toEntity(host)
        );
    }

    @GetMapping("/{id}")
    public AccommodationEntity accommodationDetail(@PathVariable long id){
        return accommodationService.findById(id);
    }
}
