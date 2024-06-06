package team07.airbnb.domain.accommodation.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import team07.airbnb.domain.BaseEntity;
import team07.airbnb.domain.accommodation.property.AccommodationLocation;
import team07.airbnb.domain.accommodation.property.AccommodationType;
import team07.airbnb.domain.accommodation.property.RoomInformation;
import team07.airbnb.domain.user.entity.UserEntity;

import java.util.List;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "ACCOMMODATION")
public class AccommodationEntity extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    @ManyToOne
    private UserEntity host;
    private AccommodationType type;

    @Embedded
    private RoomInformation roomInformation;

    @Embedded
    private AccommodationLocation address;

    // Description
    private String name;
    private String description;
    @OneToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = "accommodation_id")
    private List<Pictures> pictures;
    private int basePricePerDay;

    public void addPicture(String url) {
        pictures.add(new Pictures(this.id, url));
    }
}
