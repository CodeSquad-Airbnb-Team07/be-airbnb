package team07.airbnb.domain.booking.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import team07.airbnb.domain.BaseEntity;
import team07.airbnb.domain.booking.price_policy.discount.DiscountPolicyEntity;
import team07.airbnb.domain.booking.property.BookingStatus;
import team07.airbnb.domain.payment.PaymentEntity;
import team07.airbnb.domain.user.entity.UserEntity;
import team07.airbnb.domain.product.entity.ProductEntity;

import java.time.LocalDate;
import java.util.List;

@Entity
@Getter
@Table(name = "BOOKING")
public class BookingEntity extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    @OneToMany
    private List<ProductEntity> products;
    @ManyToOne
    private UserEntity booker;
    private int adultHeadcount;
    private int kidHeadcount;

    private LocalDate checkin;
    private LocalDate checkout;
    private BookingStatus status;

    @ManyToOne
    private DiscountPolicyEntity discountPolicyEntity;

    @OneToOne
    private PaymentEntity payment;
}
