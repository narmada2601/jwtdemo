namespace WebApplication1.model
{
    public class User
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string? Email { get; set; }
        public string? Password { get; set; }
    }
}
