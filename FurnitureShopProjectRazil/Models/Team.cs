namespace FurnitureShopProjectRazil.Models
{
    public class Team
    {
        public int Id { get; set; }
        public string Fullname { get; set; }
        public string ImagePath { get; set; }
        public string Biography { get; set; }
        public ICollection<Testimonial> Testimonials { get; set; }

        public int RoleId { get; set; }
        public Role Role { get; set; }

        public int UserId { get; set; }
        public User User { get; set; }
    }
}
